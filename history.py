"""Historical DNS record collection for DNSDumpster.

DNSDumpster can keep local snapshots of every report and, when an API key is
configured, merge them with SecurityTrails passive-DNS history.  The public
result is a JSON-friendly dictionary so it can be dropped straight into the
existing report.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence
from urllib.parse import quote

import requests


DEFAULT_HISTORY_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT")
SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/history/{domain}/dns/{type}"


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def normalize_domain(domain: str) -> str:
    text = str(domain or "").strip().lower()
    if text.startswith("http://") or text.startswith("https://"):
        from urllib.parse import urlparse

        text = urlparse(text).netloc
    text = text.rstrip(".")
    if not text:
        raise ValueError("a domain is required")
    return text


def default_history_db() -> str:
    configured = os.environ.get("DNSDUMPSTER_HISTORY_DB")
    if configured:
        return configured
    return str(Path.home() / ".dnsdumpster" / "history.sqlite3")


def _as_text(value) -> str:
    if isinstance(value, str):
        return value.strip().strip('"')
    if isinstance(value, dict):
        for key in (
            "ip",
            "value",
            "hostname",
            "exchange",
            "name",
            "nameserver",
            "target",
            "text",
            "data",
            "address",
        ):
            if key in value and value[key] not in (None, ""):
                return _as_text(value[key])
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value).strip()


def flatten_report(domain: str, report: Mapping) -> list[dict]:
    """Flatten a DNSDumpster report into ``(type, name, value)`` records."""

    domain = normalize_domain(domain)
    records = []
    seen = set()

    def add(record_type, name, value):
        record_type = str(record_type).upper()
        value = _as_text(value)
        if not value:
            return
        key = (record_type, name, value)
        if key in seen:
            return
        seen.add(key)
        records.append({"type": record_type, "name": name, "value": value})

    ns_records = report.get("ns") or []
    if isinstance(ns_records, (str, dict)):
        ns_records = [ns_records]
    for item in ns_records:
        if isinstance(item, dict):
            add("NS", domain, item.get("ns") or item.get("value"))
            if item.get("ip"):
                add("A", _as_text(item.get("ns") or domain), item.get("ip"))
        else:
            add("NS", domain, item)

    for key in ("A", "AAAA", "CNAME", "SOA", "SRV"):
        values = report.get(key) or []
        if isinstance(values, (str, dict)):
            values = [values]
        for item in values:
            name = domain
            value = item
            if isinstance(item, dict):
                name = _as_text(item.get("name") or item.get("host") or domain)
                value = (
                    item.get("value")
                    or item.get("ip")
                    or item.get("target")
                    or item.get("data")
                )
            add(key, name, value)

    mx = report.get("mx") or []
    if isinstance(mx, (str, dict)):
        mx = [mx]
    for item in mx:
        if isinstance(item, dict):
            add("MX", domain, item.get("exchange") or item.get("value"))
        else:
            add("MX", domain, item)

    txt = report.get("txt") or []
    if isinstance(txt, (str, dict)):
        txt = [txt]
    for item in txt:
        add("TXT", domain, item)

    subdomains = report.get("subdomains") or []
    if isinstance(subdomains, (str, dict)):
        subdomains = [subdomains]
    for item in subdomains:
        if not isinstance(item, dict):
            continue
        name = _as_text(item.get("subdomain") or item.get("name") or domain)
        if item.get("subdomain_ip"):
            add("A", name, item.get("subdomain_ip"))
        if item.get("ipv6"):
            add("AAAA", name, item.get("ipv6"))

    return records


class DNSHistoryStore:
    """SQLite-backed DNS history using one row per observed record."""

    def __init__(self, path: Optional[str] = None):
        self.path = str(path or default_history_db())
        self._memory_connection = None

    def _connect(self):
        if self.path == ":memory:":
            if self._memory_connection is None:
                self._memory_connection = sqlite3.connect(":memory:", timeout=10)
                self._initialize(self._memory_connection)
            return self._memory_connection
        parent = Path(self.path).expanduser().parent
        parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        self._initialize(connection)
        return connection

    def _initialize(self, connection):
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                source TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_domain
                ON snapshots(domain, recorded_at);
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                record_type TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER,
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
                    ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_records_domain_type
                ON records(record_type, name);
            """
        )

    def record(
        self,
        domain: str,
        report_or_records,
        *,
        recorded_at: Optional[str] = None,
        source: str = "dnsdumpster",
    ) -> dict:
        domain = normalize_domain(domain)
        if isinstance(report_or_records, Mapping):
            records = flatten_report(domain, report_or_records)
        else:
            records = []
            for item in report_or_records or []:
                if isinstance(item, Mapping):
                    records.append(
                        {
                            "type": str(item.get("type", "")).upper(),
                            "name": _as_text(item.get("name") or domain),
                            "value": _as_text(item.get("value", "")),
                            "ttl": item.get("ttl"),
                        }
                    )
                elif isinstance(item, (tuple, list)) and len(item) >= 3:
                    records.append(
                        {
                            "type": str(item[0]).upper(),
                            "name": _as_text(item[1]),
                            "value": _as_text(item[2]),
                            "ttl": item[3] if len(item) > 3 else None,
                        }
                    )

        recorded_at = recorded_at or _utcnow()
        records = [record for record in records if record.get("value")]
        connection = self._connect()
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO snapshots(domain, recorded_at, source) VALUES (?, ?, ?)",
                    (domain, recorded_at, source),
                )
                snapshot_id = cursor.lastrowid
                connection.executemany(
                    """
                    INSERT INTO records(snapshot_id, record_type, name, value, ttl)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            snapshot_id,
                            record["type"],
                            record.get("name") or domain,
                            record["value"],
                            record.get("ttl"),
                        )
                        for record in records
                    ],
                )
        finally:
            if self.path != ":memory:":
                connection.close()
        return {
            "snapshot_id": snapshot_id,
            "domain": domain,
            "recorded_at": recorded_at,
            "record_count": len(records),
        }

    def query(
        self,
        domain: str,
        record_types: Optional[Sequence[str]] = None,
        *,
        limit: int = 2000,
    ) -> dict:
        domain = normalize_domain(domain)
        types = tuple(str(item).upper() for item in (record_types or DEFAULT_HISTORY_TYPES))
        placeholders = ",".join("?" for _ in types)
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT r.record_type, r.name, r.value,
                       MIN(s.recorded_at) AS first_seen,
                       MAX(s.recorded_at) AS last_seen,
                       COUNT(DISTINCT r.snapshot_id) AS observations
                FROM records r
                JOIN snapshots s ON s.id = r.snapshot_id
                WHERE s.domain = ? AND r.record_type IN ({0})
                GROUP BY r.record_type, r.name, r.value
                ORDER BY r.record_type, r.name, r.value
                LIMIT ?
                """.format(placeholders),
                (domain, *types, max(int(limit), 1)),
            ).fetchall()
        finally:
            if self.path != ":memory:":
                connection.close()

        records = {record_type: [] for record_type in types}
        for record_type, name, value, first_seen, last_seen, observations in rows:
            records.setdefault(record_type, []).append(
                {
                    "name": name,
                    "value": value,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "observations": observations,
                    "source": "local",
                }
            )
        return {
            "provider": "local",
            "status": "ok",
            "storage": self.path,
            "records": records,
            "count": sum(len(items) for items in records.values()),
        }


class SecurityTrailsHistoryProvider:
    """SecurityTrails passive-DNS history provider.

    SecurityTrails requires an API key.  Without ``SECURITYTRAILS_API_KEY`` the
    provider is reported as ``unconfigured`` instead of aborting the report.
    """

    name = "securitytrails"
    base_url = SECURITYTRAILS_URL

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        session: Optional[requests.Session] = None,
        timeout: float = 8.0,
    ):
        self.api_key = api_key or os.environ.get("SECURITYTRAILS_API_KEY", "")
        self.session = session or requests.Session()
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _parse_records(self, domain: str, record_type: str, payload) -> list[dict]:
        results = []
        raw_records = []
        if isinstance(payload, Mapping):
            raw_records = payload.get("records") or payload.get("data") or []
        elif isinstance(payload, list):
            raw_records = payload

        for item in raw_records:
            if not isinstance(item, Mapping):
                values = [_as_text(item)]
                first_seen = last_seen = None
            else:
                first_seen = item.get("first_seen") or item.get("firstSeen")
                last_seen = item.get("last_seen") or item.get("lastSeen")
                values = item.get("values")
                if values is None:
                    values = [
                        item.get(key)
                        for key in (
                            "value",
                            "ip",
                            "hostname",
                            "exchange",
                            "name",
                            "nameserver",
                            "target",
                            "text",
                        )
                        if item.get(key) not in (None, "")
                    ]
                if not isinstance(values, (list, tuple)):
                    values = [values]
            for value in values:
                text = _as_text(value)
                if not text:
                    continue
                results.append(
                    {
                        "name": domain,
                        "value": text,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "observations": None,
                        "source": self.name,
                    }
                )
        return results

    def query(
        self,
        domain: str,
        record_types: Optional[Sequence[str]] = None,
    ) -> dict:
        domain = normalize_domain(domain)
        types = tuple(str(item).upper() for item in (record_types or DEFAULT_HISTORY_TYPES))
        records = {record_type: [] for record_type in types}
        if not self.configured:
            return {
                "provider": self.name,
                "status": "unconfigured",
                "records": records,
                "count": 0,
                "reason": "SECURITYTRAILS_API_KEY is not set",
            }

        errors = []
        headers = {
            "Accept": "application/json",
            "APIKEY": self.api_key,
            "User-Agent": "dnsdumpster/history",
        }
        for record_type in types:
            url = self.base_url.format(
                domain=quote(domain, safe=""),
                type=quote(record_type.lower(), safe=""),
            )
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                if response.status_code == 404:
                    continue
                if response.status_code in (401, 403):
                    errors.append("SecurityTrails rejected the API key")
                    break
                if response.status_code == 429:
                    errors.append("SecurityTrails rate limit reached")
                    break
                response.raise_for_status()
                payload = response.json()
                records[record_type].extend(
                    self._parse_records(domain, record_type, payload)
                )
            except Exception as exc:
                errors.append("{0}: {1}".format(record_type, exc))

        return {
            "provider": self.name,
            "status": "partial" if errors else "ok",
            "records": records,
            "count": sum(len(items) for items in records.values()),
            "errors": errors,
        }


def _merge_provider_records(target: dict, provider_result: Mapping):
    records = provider_result.get("records") or {}
    for record_type, items in records.items():
        target.setdefault(record_type, [])
        for item in items:
            if not isinstance(item, Mapping):
                item = {"value": item}
            merged = dict(item)
            merged.setdefault("name", "")
            merged.setdefault("value", "")
            target[record_type].append(merged)


def query_dns_history(
    domain: str,
    *,
    record_types: Optional[Sequence[str]] = None,
    db_path: Optional[str] = None,
    api_key: Optional[str] = None,
    include_local: bool = True,
    include_securitytrails: bool = True,
    providers: Optional[Sequence] = None,
    timeout: float = 8.0,
) -> dict:
    """Return historical records from local snapshots and passive DNS."""

    domain = normalize_domain(domain)
    types = tuple(str(item).upper() for item in (record_types or DEFAULT_HISTORY_TYPES))
    provider_results = []
    merged = {record_type: [] for record_type in types}

    if include_local:
        try:
            local = DNSHistoryStore(db_path).query(domain, types)
        except Exception as exc:
            local = {
                "provider": "local",
                "status": "error",
                "records": {},
                "count": 0,
                "errors": [str(exc)],
            }
        provider_results.append(local)
        _merge_provider_records(merged, local)

    if providers is None and include_securitytrails:
        providers = [SecurityTrailsHistoryProvider(api_key=api_key, timeout=timeout)]
    for provider in providers or []:
        try:
            result = provider.query(domain, types)
        except Exception as exc:
            result = {
                "provider": getattr(provider, "name", provider.__class__.__name__),
                "status": "error",
                "records": {},
                "count": 0,
                "errors": [str(exc)],
            }
        provider_results.append(result)
        _merge_provider_records(merged, result)

    # Deduplicate identical values while preserving the earliest/latest time.
    deduped = {}
    for record_type, items in merged.items():
        by_key = {}
        for item in items:
            key = (item.get("name", ""), item.get("value", ""))
            if key not in by_key:
                by_key[key] = dict(item)
                continue
            existing = by_key[key]
            for timestamp, reducer in (
                ("first_seen", min),
                ("last_seen", max),
            ):
                values = [
                    value
                    for value in (existing.get(timestamp), item.get(timestamp))
                    if value
                ]
                if values:
                    existing[timestamp] = reducer(values)
            sources = {
                source
                for source in (existing.get("source"), item.get("source"))
                if source
            }
            existing["source"] = ",".join(sorted(sources))
        deduped[record_type] = sorted(
            by_key.values(), key=lambda row: (row.get("name", ""), row.get("value", ""))
        )

    return {
        "domain": domain,
        "queried_at": _utcnow(),
        "record_types": list(types),
        "records": deduped,
        "count": sum(len(items) for items in deduped.values()),
        "providers": provider_results,
    }


def record_dns_history(
    domain: str,
    report: Mapping,
    *,
    db_path: Optional[str] = None,
    recorded_at: Optional[str] = None,
) -> dict:
    """Persist the current report as a local history snapshot."""

    return DNSHistoryStore(db_path).record(
        domain, report, recorded_at=recorded_at, source="dnsdumpster"
    )


# Convenient aliases for integrations that use "historical" wording.
get_dns_history = query_dns_history
query_historical_dns = query_dns_history


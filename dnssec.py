"""DNSSEC chain validation helpers used by the DNSDumpster report.

The validator deliberately performs the chain walk itself instead of relying on
the AD flag of a recursive resolver.  This makes the result useful for
reconnaissance: the report contains the validated delegation path, the keys
used at every zone cut and a stable ``secure``/``insecure``/``bogus`` status.
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdataset
import dns.rcode
import dns.rdata
import dns.rrset
import requests


ROOT_TRUST_ANCHORS = (
    "20326 8 2 "
    "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "38696 8 2 "
    "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
)

DEFAULT_DOH_ENDPOINTS = (
    os.environ.get("DNSDUMPSTER_DOH_URL", "https://cloudflare-dns.com/dns-query"),
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
)

# Ten stable, public names used by the live dig-consistency test.  Six are
# DNSSEC signed and four are unsigned delegations.  The list is intentionally
# explicit so a test run tells us which domains were compared.
DNSSEC_DIG_TEST_DOMAINS = (
    "cloudflare.com",
    "ietf.org",
    "nlnetlabs.nl",
    "verisign.com",
    "nic.cz",
    "internetsociety.org",
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
)
DNSSEC_DIG_COMPARISON_DOMAINS = DNSSEC_DIG_TEST_DOMAINS

SECURE = "secure"
INSECURE = "insecure"
BOGUS = "bogus"
UNKNOWN = "unknown"


class DNSSECQueryError(RuntimeError):
    """Raised when a DNS query needed for validation cannot be completed."""


def _rrtype(value) -> int:
    if isinstance(value, int):
        return value
    return dns.rdatatype.from_text(str(value))


def normalize_domain(domain: str) -> dns.name.Name:
    """Return an absolute, lower-case dns.name.Name for *domain*."""

    text = str(domain or "").strip().lower()
    if text.startswith("http://") or text.startswith("https://"):
        from urllib.parse import urlparse

        text = urlparse(text).netloc
    text = text.rstrip(".")
    if not text:
        raise ValueError("a domain is required")
    try:
        return dns.name.from_text(text, origin=dns.name.root)
    except (dns.exception.DNSException, ValueError) as exc:
        raise ValueError("invalid domain: {0}".format(domain)) from exc


def _domain_text(domain: str) -> str:
    return normalize_domain(domain).to_text(omit_final_dot=True)


def _covers(rrset, rdtype: int) -> bool:
    """Return True if *rrset* is an RRSIG covering *rdtype*.

    dnspython exposed ``covers`` as a method in older releases and as a
    property in 2.9+, so accept both forms.
    """

    if rrset.rdtype != dns.rdatatype.RRSIG:
        return False
    covers = getattr(rrset, "covers", None)
    if callable(covers):
        covers = covers()
    return covers == rdtype


def find_rrset(message: dns.message.Message, name, rdtype):
    """Find an RRset in any section of *message* by owner name and type."""

    owner = dns.name.from_text(name) if not isinstance(name, dns.name.Name) else name
    wanted = _rrtype(rdtype)
    for section in (message.answer, message.authority, message.additional):
        for rrset in section:
            if rrset.name == owner and rrset.rdtype == wanted:
                return rrset
    return None


def find_rrsig(message: dns.message.Message, name, rdtype):
    """Find the RRSIG RRset covering *rdtype* at *name*, if present."""

    owner = dns.name.from_text(name) if not isinstance(name, dns.name.Name) else name
    wanted = _rrtype(rdtype)
    for section in (message.answer, message.authority, message.additional):
        for rrset in section:
            if rrset.name == owner and _covers(rrset, wanted):
                return rrset
    return None


def _message_status(message: dns.message.Message) -> str:
    return dns.rcode.to_text(message.rcode())


@dataclass
class DoHClient:
    """Small synchronous DNS-over-HTTPS client with endpoint fallback."""

    endpoints: Sequence[str] = field(default_factory=lambda: DEFAULT_DOH_ENDPOINTS)
    timeout: float = 8.0
    session: Optional[requests.Session] = None
    _active_endpoint: Optional[str] = None

    def __post_init__(self):
        if self.session is None:
            self.session = requests.Session()
        if isinstance(self.endpoints, str):
            self.endpoints = (self.endpoints,)
        self.endpoints = tuple(dict.fromkeys(self.endpoints))

    @property
    def active_endpoint(self) -> str:
        return self._active_endpoint or (self.endpoints[0] if self.endpoints else "")

    def _request(self, endpoint: str, wire: bytes, timeout: float):
        headers = {
            "Accept": "application/dns-message",
            "Content-Type": "application/dns-message",
            "User-Agent": "dnsdumpster/DNSSEC",
        }
        response = self.session.post(
            endpoint, data=wire, headers=headers, timeout=timeout
        )
        if response.status_code in (405, 415):
            encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode("ascii")
            response = self.session.get(
                endpoint,
                params={"dns": encoded},
                headers={"Accept": "application/dns-message"},
                timeout=timeout,
            )
        return response

    def query(self, name, rdtype, timeout: Optional[float] = None) -> dns.message.Message:
        owner = dns.name.from_text(name) if not isinstance(name, dns.name.Name) else name
        request = dns.message.make_query(
            owner, _rrtype(rdtype), want_dnssec=True, use_edns=True, payload=4096
        )
        wire = request.to_wire()
        timeout = self.timeout if timeout is None else timeout
        errors = []
        endpoints = list(self.endpoints)
        if self._active_endpoint in endpoints:
            endpoints.remove(self._active_endpoint)
            endpoints.insert(0, self._active_endpoint)
        for endpoint in endpoints:
            try:
                response = self._request(endpoint, wire, timeout)
                if response.status_code != 200:
                    raise DNSSECQueryError(
                        "DoH endpoint {0} returned HTTP {1}".format(
                            endpoint, response.status_code
                        )
                    )
                message = dns.message.from_wire(response.content)
                self._active_endpoint = endpoint
                return message
            except Exception as exc:  # try the next endpoint
                errors.append("{0}: {1}".format(endpoint, exc))
        raise DNSSECQueryError("; ".join(errors) or "no DoH endpoint configured")


class SystemResolverClient:
    """Client backed by dnspython's configured recursive resolver.

    It is useful for unit tests and for environments where DoH is unavailable.
    The resolver must be configured to return DNSSEC records (DO bit), otherwise
    the validator will correctly report a missing signature as ``bogus``.
    """

    def __init__(self, resolver=None, timeout: float = 8.0):
        if resolver is None:
            import dns.resolver

            resolver = dns.resolver.Resolver()
        self.resolver = resolver
        self.timeout = timeout
        self.resolver.timeout = max(float(timeout), 0.1)
        self.resolver.lifetime = max(float(timeout), 0.1)

    def query(self, name, rdtype, timeout: Optional[float] = None) -> dns.message.Message:
        owner = dns.name.from_text(name) if not isinstance(name, dns.name.Name) else name
        answer = self.resolver.resolve(
            owner, _rrtype(rdtype), lifetime=timeout or self.timeout, raise_on_no_answer=False
        )
        if answer.response is not None:
            return answer.response
        message = dns.message.Message()
        message.flags |= dns.flags.QR
        if answer.rrset is not None:
            message.answer.append(answer.rrset)
        return message


def _parse_trust_anchor(value):
    if isinstance(value, dns.rdata.Rdata) and value.rdtype == dns.rdatatype.DS:
        return value
    if isinstance(value, (tuple, list)) and not isinstance(value, str):
        if len(value) == 4:
            key_tag, algorithm, digest_type, digest = value
            text = "{0} {1} {2} {3}".format(key_tag, algorithm, digest_type, digest)
        else:
            text = " ".join(str(part) for part in value)
    else:
        text = str(value).strip()
    try:
        return dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.DS, text
        )
    except Exception as exc:
        raise ValueError("invalid root trust anchor: {0}".format(text)) from exc


def _keyset_from_rdata(zone: dns.name.Name, keys: Iterable, ttl: int = 0):
    dataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    for key in keys:
        dataset.add(key, ttl)
    return dataset


def _matching_keys(zone: dns.name.Name, dnskey_rrset, ds_rrset):
    """Return DNSKEYs matching at least one DS digest in *ds_rrset*."""

    matches = []
    for key in dnskey_rrset:
        key_tag = dns.dnssec.key_id(key)
        for ds in ds_rrset:
            if ds.key_tag != key_tag or ds.algorithm != key.algorithm:
                continue
            try:
                computed = dns.dnssec.make_ds(zone, key, ds.digest_type)
            except Exception:
                continue
            if computed.digest == ds.digest:
                matches.append(key)
                break
    return matches


def _validate_rrset(rrset, rrsig, keys, zone: dns.name.Name):
    if rrset is None:
        raise dns.dnssec.ValidationFailure("missing RRset")
    if rrsig is None:
        raise dns.dnssec.ValidationFailure("missing RRSIG")
    dns.dnssec.validate(rrset, rrsig, {zone: keys})


def _result(domain, status, *, chain=None, errors=None, **extra):
    try:
        domain_text = _domain_text(domain)
    except ValueError:
        domain_text = str(domain)
    result = {
        "domain": domain_text,
        "status": status,
        "validated": status == SECURE,
        "trust_anchor": "IANA root KSK",
        "transport": extra.pop("transport", "doh"),
        "chain": chain or [],
        "errors": list(errors or []),
    }
    result.update(extra)
    return result


def _append_chain(chain, zone, status, **details):
    entry = {
        "zone": zone.to_text(),
        "status": status,
    }
    entry.update({key: value for key, value in details.items() if value is not None})
    chain.append(entry)


def check_dnssec(
    domain: str,
    *,
    client=None,
    trust_anchors: Optional[Sequence[str]] = None,
    timeout: float = 8.0,
    validate_target: bool = True,
) -> dict:
    """Validate the DNSSEC delegation chain for *domain*.

    ``client`` only needs a ``query(name, rdtype)`` method returning a
    :class:`dns.message.Message`; this keeps the validator easy to test and
    allows callers to use system DNS or DoH.

    The returned dictionary is JSON-serializable and contains ``status``,
    ``validated``, the per-zone ``chain`` and any validation ``errors``.
    """

    try:
        name = normalize_domain(domain)
    except ValueError as exc:
        return _result(domain, UNKNOWN, errors=[str(exc)])

    domain_text = name.to_text(omit_final_dot=True)
    client = client or DoHClient(timeout=timeout)
    transport = getattr(client, "name", None) or (
        "doh" if isinstance(client, DoHClient) else client.__class__.__name__
    )
    chain = []
    errors = []
    try:
        anchors = [
            _parse_trust_anchor(item)
            for item in (trust_anchors or ROOT_TRUST_ANCHORS)
        ]
    except ValueError as exc:
        return _result(
            domain_text,
            UNKNOWN,
            errors=[str(exc)],
            transport=transport,
        )

    try:
        root_dnskey_msg = client.query(dns.name.root, dns.rdatatype.DNSKEY, timeout=timeout)
        root_dnskey = find_rrset(root_dnskey_msg, dns.name.root, dns.rdatatype.DNSKEY)
        root_sig = find_rrsig(root_dnskey_msg, dns.name.root, dns.rdatatype.DNSKEY)
        if root_dnskey is None:
            raise dns.dnssec.ValidationFailure("root DNSKEY not available")

        root_ds_rrset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        for anchor in anchors:
            root_ds_rrset.add(anchor, 0)
        trusted_root_keys = _matching_keys(dns.name.root, root_dnskey, root_ds_rrset)
        if not trusted_root_keys:
            raise dns.dnssec.ValidationFailure(
                "root DNSKEY does not match the configured trust anchors"
            )
        trusted_root_set = _keyset_from_rdata(
            dns.name.root, trusted_root_keys, root_dnskey.ttl
        )
        _validate_rrset(root_dnskey, root_sig, trusted_root_set, dns.name.root)
        _append_chain(
            chain,
            dns.name.root,
            SECURE,
            key_tag=dns.dnssec.key_id(trusted_root_keys[0]),
            algorithm=trusted_root_keys[0].algorithm,
            dnskey_count=len(root_dnskey),
            matched_keys=len(trusted_root_keys),
        )
    except Exception as exc:
        return _result(
            domain_text,
            UNKNOWN,
            chain=chain,
            errors=["root validation failed: {0}".format(exc)],
            transport=transport,
        )

    current_zone = dns.name.root
    current_keys = root_dnskey
    labels = name.labels[:-1]  # drop the root label

    for index in range(len(labels) - 1, -1, -1):
        child = dns.name.Name(labels[index:])
        if not child.is_absolute():
            child = child.derelativize(dns.name.root)
        child_text = child.to_text(omit_final_dot=True)
        try:
            ds_message = client.query(child, dns.rdatatype.DS, timeout=timeout)
        except Exception as exc:
            return _result(
                domain_text,
                UNKNOWN,
                chain=chain,
                errors=["DS lookup for {0} failed: {1}".format(child_text, exc)],
                zone=current_zone.to_text(),
                transport=transport,
            )

        ds_rrset = find_rrset(ds_message, child, dns.rdatatype.DS)
        if ds_rrset is None:
            rcode = ds_message.rcode()
            if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                return _result(
                    domain_text,
                    UNKNOWN,
                    chain=chain,
                    errors=[
                        "DS lookup for {0} returned {1}".format(
                            child_text, _message_status(ds_message)
                        )
                    ],
                    zone=current_zone.to_text(),
                    transport=transport,
                )
            if rcode == dns.rcode.NXDOMAIN:
                return _result(
                    domain_text,
                    UNKNOWN,
                    chain=chain,
                    errors=["{0} does not exist (NXDOMAIN)".format(child_text)],
                    zone=current_zone.to_text(),
                    transport=transport,
                )

            # A missing DS can mean either an unsigned delegation or just a
            # non-delegated name inside the current zone.  NS records at the
            # name distinguish the two.
            try:
                ns_message = client.query(child, dns.rdatatype.NS, timeout=timeout)
                child_ns = find_rrset(ns_message, child, dns.rdatatype.NS)
            except Exception as exc:
                return _result(
                    domain_text,
                    UNKNOWN,
                    chain=chain,
                    errors=["NS lookup for {0} failed: {1}".format(child_text, exc)],
                    zone=current_zone.to_text(),
                    transport=transport,
                )
            if child_ns is not None:
                _append_chain(
                    chain,
                    child,
                    INSECURE,
                    reason="unsigned delegation (no DS)",
                    parent_zone=current_zone.to_text(),
                )
                return _result(
                    domain_text,
                    INSECURE,
                    chain=chain,
                    zone=current_zone.to_text(),
                    transport=transport,
                    reason="no DS record at delegation",
                )
            continue

        ds_sig = find_rrsig(ds_message, child, dns.rdatatype.DS)
        try:
            _validate_rrset(ds_rrset, ds_sig, current_keys, current_zone)
        except Exception as exc:
            _append_chain(
                chain,
                child,
                BOGUS,
                reason="DS signature validation failed",
            )
            return _result(
                domain_text,
                BOGUS,
                chain=chain,
                errors=["DS signature for {0}: {1}".format(child_text, exc)],
                zone=current_zone.to_text(),
                transport=transport,
                reason="invalid DS signature",
            )

        try:
            dnskey_message = client.query(child, dns.rdatatype.DNSKEY, timeout=timeout)
        except Exception as exc:
            return _result(
                domain_text,
                UNKNOWN,
                chain=chain,
                errors=["DNSKEY lookup for {0} failed: {1}".format(child_text, exc)],
                zone=current_zone.to_text(),
                transport=transport,
            )

        try:
            child_dnskey = find_rrset(
                dnskey_message, child, dns.rdatatype.DNSKEY
            )
            child_sig = find_rrsig(
                dnskey_message, child, dns.rdatatype.DNSKEY
            )
            if dnskey_message.rcode() not in (
                dns.rcode.NOERROR,
                dns.rcode.NXDOMAIN,
            ):
                raise dns.dnssec.ValidationFailure(
                    "DNSKEY lookup returned {0}".format(
                        _message_status(dnskey_message)
                    )
                )
            if child_dnskey is None:
                raise dns.dnssec.ValidationFailure("DNSKEY RRset is missing")
            matched = _matching_keys(child, child_dnskey, ds_rrset)
            if not matched:
                raise dns.dnssec.ValidationFailure(
                    "no DNSKEY matches the DS record"
                )
            matched_set = _keyset_from_rdata(child, matched, child_dnskey.ttl)
            _validate_rrset(child_dnskey, child_sig, matched_set, child)
        except Exception as exc:
            _append_chain(
                chain,
                child,
                BOGUS,
                reason="DNSKEY validation failed",
            )
            return _result(
                domain_text,
                BOGUS,
                chain=chain,
                errors=["DNSKEY for {0}: {1}".format(child_text, exc)],
                zone=current_zone.to_text(),
                transport=transport,
                reason="invalid DNSKEY or DS/DNSKEY mismatch",
            )

        current_zone = child
        current_keys = child_dnskey
        _append_chain(
            chain,
            child,
            SECURE,
            key_tag=dns.dnssec.key_id(matched[0]),
            algorithm=matched[0].algorithm,
            dnskey_count=len(child_dnskey),
            matched_keys=len(matched),
            ds_digest_type=ds_rrset[0].digest_type if len(ds_rrset) else None,
        )

    # The delegation chain is secure.  Validate an actual RRset at the target
    # when one is available; this catches broken signatures that would be
    # missed by only looking at DNSKEYs.
    target_checks = []
    if validate_target:
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.CNAME):
            try:
                message = client.query(name, rdtype, timeout=timeout)
            except Exception as exc:
                errors.append(
                    "{0} lookup failed: {1}".format(
                        dns.rdatatype.to_text(rdtype), exc
                    )
                )
                continue
            rrset = find_rrset(message, name, rdtype)
            if rrset is None:
                continue
            sig = find_rrsig(message, name, rdtype)
            try:
                _validate_rrset(rrset, sig, current_keys, current_zone)
            except Exception as exc:
                target = {
                    "type": dns.rdatatype.to_text(rdtype),
                    "status": BOGUS,
                }
                target_checks.append(target)
                return _result(
                    domain_text,
                    BOGUS,
                    chain=chain,
                    errors=[
                        "{0} RRset signature validation failed: {1}".format(
                            dns.rdatatype.to_text(rdtype), exc
                        )
                    ],
                    zone=current_zone.to_text(),
                    target_records=target_checks,
                    transport=transport,
                    reason="invalid target RRset signature",
                )
            target_checks.append(
                {
                    "type": dns.rdatatype.to_text(rdtype),
                    "status": SECURE,
                    "count": len(rrset),
                }
            )
            break

    return _result(
        domain_text,
        SECURE,
        chain=chain,
        errors=errors,
        zone=current_zone.to_text(),
        target_records=target_checks,
        transport=transport,
    )


# Backwards/forwards friendly aliases for callers that use a more explicit name.
validate_dnssec_chain = check_dnssec
verify_dnssec_chain = check_dnssec
validate_dnssec = check_dnssec
get_dnssec_status = check_dnssec


_DIG_STATUS_RE = re.compile(r"status:\s*([A-Z]+)", re.IGNORECASE)


def _run_dig(args: Sequence[str], timeout: float) -> dict:
    command = ["dig", "+time={0}".format(max(int(timeout), 1)), "+tries=1"] + list(args)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except FileNotFoundError:
        return {
            "status": UNKNOWN,
            "error": "dig executable not found",
            "command": command,
            "answer": [],
        }
    except subprocess.TimeoutExpired:
        return {
            "status": UNKNOWN,
            "error": "dig timed out",
            "command": command,
            "answer": [],
        }

    output = (completed.stdout or "") + (completed.stderr or "")
    rcode_match = _DIG_STATUS_RE.search(output)
    rcode = rcode_match.group(1).upper() if rcode_match else ""
    answers = []
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        answers.append(line)
    error = None
    if completed.returncode != 0:
        error = output.strip() or "dig failed"
    return {
        "status": UNKNOWN,
        "rcode": rcode,
        "answer": answers,
        "command": command,
        "error": error,
    }


def dig_dnssec_status(
    domain: str,
    *,
    timeout: float = 5.0,
    resolver: Optional[str] = None,
) -> dict:
    """Classify a domain using the records returned by ``dig +dnssec``.

    This is intentionally a record-level consistency probe, not a replacement
    for the cryptographic validation above.  A name with DS and DNSKEY records
    is reported as ``secure``; a delegation without DS is ``insecure``; DS
    without DNSKEY is ``bogus``.  Many stub resolvers do not return RRSIGs, so
    RRSIG presence is recorded but not required for the comparison.
    """

    try:
        name = _domain_text(domain)
    except ValueError as exc:
        return {"domain": domain, "status": UNKNOWN, "error": str(exc)}

    resolver_args = ["@{0}".format(resolver)] if resolver else []
    ds = _run_dig(
        ["+dnssec", "+noall", "+comments", "+answer"] + resolver_args + ["DS", name],
        timeout,
    )
    dnskey = _run_dig(
        ["+dnssec", "+noall", "+comments", "+answer"] + resolver_args + ["DNSKEY", name],
        timeout,
    )
    ad = _run_dig(
        ["+dnssec", "+noall", "+comments"] + resolver_args + ["A", name],
        timeout,
    )

    ds_records = ds["answer"]
    dnskey_records = dnskey["answer"]
    has_ds = bool(ds_records)
    has_dnskey = bool(dnskey_records)
    rcode = (ds.get("rcode") or "").upper()
    error = ds.get("error") or dnskey.get("error")
    ds_failed = bool(ds.get("error")) or rcode not in ("", "NOERROR", "NXDOMAIN")
    dnskey_failed = bool(dnskey.get("error")) or (dnskey.get("rcode") or "").upper() not in (
        "",
        "NOERROR",
        "NXDOMAIN",
    )

    if (ds_failed and not has_ds) or (dnskey_failed and not has_dnskey):
        status = UNKNOWN
    elif has_ds and has_dnskey:
        status = SECURE
    elif has_ds:
        status = BOGUS
    elif rcode in ("", "NOERROR", "NXDOMAIN"):
        status = INSECURE
    else:
        status = UNKNOWN

    return {
        "domain": name,
        "status": status,
        "has_ds": has_ds,
        "has_dnskey": has_dnskey,
        "ds": ds_records,
        "dnskey": dnskey_records,
        "rcode": rcode,
        "error": error,
        "commands": {
            "ds": ds.get("command"),
            "dnskey": dnskey.get("command"),
            "a": ad.get("command"),
        },
    }


def compare_dnssec_with_dig(
    domain: str,
    *,
    client=None,
    timeout: float = 8.0,
    dig_timeout: float = 5.0,
    dig_resolver: Optional[str] = None,
) -> dict:
    """Compare this module's status with ``dig +dnssec`` for one domain."""

    ours = check_dnssec(domain, client=client, timeout=timeout)
    dig = dig_dnssec_status(domain, timeout=dig_timeout, resolver=dig_resolver)
    return {
        "domain": ours.get("domain", domain),
        "dnssec": ours,
        "dig": dig,
        "dnssec_status": ours.get("status"),
        "dig_status": dig.get("status"),
        "consistent": ours.get("status") == dig.get("status"),
    }


def compare_dnssec_domains_with_dig(
    domains: Sequence[str] = DNSSEC_DIG_TEST_DOMAINS,
    **kwargs,
) -> list[dict]:
    """Run :func:`compare_dnssec_with_dig` over *domains*."""

    return [compare_dnssec_with_dig(domain, **kwargs) for domain in domains]


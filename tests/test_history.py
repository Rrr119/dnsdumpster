import json

import history


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP {0}".format(self.status_code))


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        record_type = url.rsplit("/", 1)[-1].upper()
        return self.responses.get(record_type, FakeResponse(404))


def test_local_history_records_changes(tmp_path):
    db_path = str(tmp_path / "history.sqlite3")
    store = history.DNSHistoryStore(db_path)
    first = {
        "ns": [{"ns": "ns1.example.com", "ip": "192.0.2.53"}],
        "mx": "mail.example.com.",
        "txt": ["v=spf1 -all"],
        "subdomains": [
            {"subdomain": "www.example.com", "subdomain_ip": "192.0.2.10"}
        ],
    }
    second = {
        "ns": [{"ns": "ns1.example.com", "ip": "192.0.2.53"}],
        "mx": "mail.example.com.",
        "txt": ["v=spf1 -all"],
        "subdomains": [
            {"subdomain": "www.example.com", "subdomain_ip": "192.0.2.11"}
        ],
    }

    store.record("example.com", first, recorded_at="2026-01-01T00:00:00+00:00")
    store.record("example.com", second, recorded_at="2026-02-01T00:00:00+00:00")
    result = store.query("example.com")

    a_values = {
        item["value"]: item for item in result["records"]["A"]
    }
    assert set(a_values) == {"192.0.2.10", "192.0.2.11", "192.0.2.53"}
    assert a_values["192.0.2.10"]["first_seen"] == "2026-01-01T00:00:00+00:00"
    assert a_values["192.0.2.10"]["last_seen"] == "2026-01-01T00:00:00+00:00"
    assert a_values["192.0.2.53"]["observations"] == 2
    assert result["records"]["MX"][0]["value"] == "mail.example.com."
    assert result["records"]["TXT"][0]["value"] == "v=spf1 -all"


def test_in_memory_history_store():
    store = history.DNSHistoryStore(":memory:")
    store.record("example.com", {"mx": "mail.example.com."})
    result = store.query("example.com", ["MX"])

    assert result["records"]["MX"][0]["value"] == "mail.example.com."


def test_securitytrails_provider_parses_history():
    payload = {
        "records": [
            {
                "first_seen": "2020-01-01",
                "last_seen": "2021-01-01",
                "values": [{"ip": "192.0.2.20"}],
            }
        ]
    }
    provider = history.SecurityTrailsHistoryProvider(
        api_key="test-key",
        session=FakeSession({"A": FakeResponse(200, payload)}),
    )
    result = provider.query("example.com", ["A", "MX"])

    assert result["status"] == "ok"
    assert result["records"]["A"][0]["value"] == "192.0.2.20"
    assert result["records"]["A"][0]["first_seen"] == "2020-01-01"
    assert result["records"]["MX"] == []
    assert len(provider.session.calls) == 2
    assert provider.session.calls[0][1]["headers"]["APIKEY"] == "test-key"


def test_securitytrails_without_key_is_unconfigured():
    provider = history.SecurityTrailsHistoryProvider(
        api_key="", session=FakeSession({})
    )
    result = provider.query("example.com", ["A"])

    assert result["status"] == "unconfigured"
    assert result["count"] == 0
    assert not provider.session.calls


def test_query_history_merges_local_and_remote(tmp_path):
    db_path = str(tmp_path / "history.sqlite3")
    history.record_dns_history(
        "example.com",
        {"txt": ["local-value"]},
        db_path=db_path,
        recorded_at="2026-01-01T00:00:00+00:00",
    )
    remote_payload = {
        "records": [
            {
                "first_seen": "2019-01-01",
                "last_seen": "2019-02-01",
                "values": [{"data": "remote-value"}],
            }
        ]
    }
    provider = history.SecurityTrailsHistoryProvider(
        api_key="test-key",
        session=FakeSession({"TXT": FakeResponse(200, remote_payload)}),
    )

    result = history.query_dns_history(
        "example.com",
        record_types=["TXT"],
        db_path=db_path,
        providers=[provider],
    )

    values = {item["value"] for item in result["records"]["TXT"]}
    assert values == {"local-value", "remote-value"}
    assert result["count"] == 2
    assert [item["provider"] for item in result["providers"]] == [
        "local",
        "securitytrails",
    ]
    json.dumps(result)  # result must remain report/JSON friendly


def test_flatten_report_includes_ns_ip_and_subdomain_a():
    records = history.flatten_report(
        "example.com",
        {
            "ns": [{"ns": "ns1.example.com.", "ip": "192.0.2.53"}],
            "subdomains": [
                {"subdomain": "www.example.com", "subdomain_ip": "192.0.2.10"}
            ],
        },
    )

    assert ("NS", "example.com", "ns1.example.com.") in {
        (item["type"], item["name"], item["value"]) for item in records
    }
    assert ("A", "www.example.com", "192.0.2.10") in {
        (item["type"], item["name"], item["value"]) for item in records
    }


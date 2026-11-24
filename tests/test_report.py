import json
from unittest.mock import patch

import dnsdumpster


class FakeARecord:
    def __init__(self, address):
        self.address = address


def _patch_dns_lookups():
    return [
        patch.object(dnsdumpster, "query_A_records", return_value=[FakeARecord("192.0.2.10")]),
        patch.object(dnsdumpster, "locate_asn_info", return_value={"asn": "64496"}),
        patch.object(dnsdumpster, "get_server_type", return_value="test-server"),
        patch.object(dnsdumpster, "query_host_mx", return_value="mail.example.com."),
        patch.object(
            dnsdumpster,
            "query_host_ns",
            return_value=[{"ns": "ns1.example.com.", "ip": "192.0.2.53"}],
        ),
        patch.object(dnsdumpster, "query_host_txt", return_value=["v=spf1 -all"]),
    ]


def test_report_keeps_legacy_keys_and_adds_dnssec_and_history():
    patches = _patch_dns_lookups()
    for item in patches:
        item.start()
    try:
        report = dnsdumpster.build_dns_report(
            "example.com",
            ["www.example.com"],
            dnssec_checker=lambda domain, timeout=8.0: {
                "domain": domain,
                "status": "secure",
                "validated": True,
            },
            history_recorder=lambda *args, **kwargs: {"record_count": 1},
            history_query=lambda domain, **kwargs: {
                "domain": domain,
                "records": {"A": []},
                "count": 0,
            },
        )
    finally:
        for item in patches:
            item.stop()

    assert set(report) == {
        "host",
        "server",
        "mx",
        "ns",
        "asn",
        "subdomains",
        "txt",
        "dnssec",
        "history",
    }
    assert report["host"] == "example.com"
    assert report["server"] == "test-server"
    assert report["mx"] == "mail.example.com."
    assert report["ns"] == [{"ns": "ns1.example.com.", "ip": "192.0.2.53"}]
    assert report["txt"] == ["v=spf1 -all"]
    assert report["subdomains"][0] == {
        "subdomain": "www.example.com",
        "subdomain_ip": "192.0.2.10",
        "asn": {"asn": "64496"},
        "server": "test-server",
    }
    assert report["dnssec"]["status"] == "secure"
    assert report["history"]["count"] == 0
    json.dumps(report)


def test_report_survives_dnssec_and_history_failures():
    patches = _patch_dns_lookups()
    for item in patches:
        item.start()
    try:
        report = dnsdumpster.build_dns_report(
            "example.com",
            [],
            dnssec_checker=lambda domain, timeout=8.0: (_ for _ in ()).throw(
                RuntimeError("dnssec failed")
            ),
            history_recorder=lambda *args, **kwargs: (_ for _ in ()).throw(
                RuntimeError("history write failed")
            ),
            history_query=lambda domain, **kwargs: (_ for _ in ()).throw(
                RuntimeError("history read failed")
            ),
        )
    finally:
        for item in patches:
            item.stop()

    assert report["dnssec"]["status"] == "unknown"
    assert "dnssec failed" in report["dnssec"]["errors"][0]
    assert report["history"]["status"] == "error"
    assert "history read failed" in report["history"]["errors"][0]


def test_report_can_disable_new_sections():
    patches = _patch_dns_lookups()
    for item in patches:
        item.start()
    try:
        report = dnsdumpster.build_dns_report(
            "example.com",
            [],
            include_dnssec=False,
            include_history=False,
        )
    finally:
        for item in patches:
            item.stop()

    assert "dnssec" not in report
    assert "history" not in report
    assert set(report) == {
        "host",
        "server",
        "mx",
        "ns",
        "asn",
        "subdomains",
        "txt",
    }


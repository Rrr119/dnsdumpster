import pytest

pytest.importorskip("cryptography")

import dns.dnssec  # noqa: E402
import dns.flags  # noqa: E402
import dns.message  # noqa: E402
import dns.name  # noqa: E402
import dns.rdata  # noqa: E402
import dns.rdataclass  # noqa: E402
import dns.rdatatype  # noqa: E402
import dns.rcode  # noqa: E402
import dns.rrset  # noqa: E402

import dnssec  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402


def _new_zone(name, flags=257):
    private_key = ec.generate_private_key(ec.SECP256R1())
    dnskey = dns.dnssec.make_dnskey(
        private_key.public_key(), dns.dnssec.ECDSAP256SHA256, flags=flags
    )
    owner = dns.name.from_text(name)
    dnskey_rrset = dns.rrset.RRset(
        owner, dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    dnskey_rrset.add(dnskey, 300)
    return {
        "name": owner,
        "private_key": private_key,
        "dnskey": dnskey,
        "dnskey_rrset": dnskey_rrset,
    }


def _rrset(name, rdtype, rdatas, ttl=300):
    rrset = dns.rrset.RRset(
        dns.name.from_text(name),
        dns.rdataclass.IN,
        dns.rdatatype.from_text(rdtype),
    )
    for rdata in rdatas:
        rrset.add(rdata, ttl)
    return rrset


def _signed_message(rrset, zone):
    signature = dns.dnssec.sign(
        rrset,
        zone["private_key"],
        zone["name"],
        zone["dnskey"],
        lifetime=3600,
    )
    signature_rrset = _rrset(
        rrset.name.to_text(), "RRSIG", [signature]
    )
    message = dns.message.Message(id=0)
    message.flags |= dns.flags.QR | dns.flags.RA
    message.answer.append(rrset)
    message.answer.append(signature_rrset)
    return message


def _ds_message(child, parent):
    ds = dns.dnssec.make_ds(
        child["name"], child["dnskey"], dns.dnssec.DSDigest.SHA256
    )
    rrset = _rrset(child["name"].to_text(), "DS", [ds])
    return _signed_message(rrset, parent)


def _empty_message(rcode=dns.rcode.NOERROR):
    message = dns.message.Message(id=0)
    message.flags |= dns.flags.QR | dns.flags.RA
    message.set_rcode(rcode)
    return message


def _ns_message(zone_name):
    ns_name = dns.name.from_text("ns1." + zone_name.to_text())
    rrset = _rrset(
        zone_name.to_text(),
        "NS",
        [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns_name.to_text())],
    )
    message = dns.message.Message(id=0)
    message.flags |= dns.flags.QR | dns.flags.RA
    message.answer.append(rrset)
    return message


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.queries = []

    def query(self, name, rdtype, timeout=None):
        owner = name if isinstance(name, dns.name.Name) else dns.name.from_text(name)
        type_text = dns.rdatatype.to_text(rdtype).upper()
        self.queries.append((owner.to_text(), type_text))
        value = self.responses.get((owner.to_text(), type_text))
        if isinstance(value, Exception):
            raise value
        if value is None:
            return _empty_message()
        return value


def _build_chain(*, child_ds=True, child_dnskey=True):
    root = _new_zone(".")
    com = _new_zone("com.")
    example = _new_zone("example.com.")
    responses = {
        (".", "DNSKEY"): _signed_message(root["dnskey_rrset"], root),
        ("com.", "DS"): _ds_message(com, root),
        ("com.", "DNSKEY"): _signed_message(com["dnskey_rrset"], com),
    }
    if child_ds:
        responses[("example.com.", "DS")] = _ds_message(example, com)
    else:
        responses[("example.com.", "NS")] = _ns_message(example["name"])
    if child_dnskey:
        responses[("example.com.", "DNSKEY")] = _signed_message(
            example["dnskey_rrset"], example
        )

    answer = _rrset(
        "example.com.",
        "A",
        [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.10")],
    )
    responses[("example.com.", "A")] = _signed_message(answer, example)
    root_ds = dns.dnssec.make_ds(
        root["name"], root["dnskey"], dns.dnssec.DSDigest.SHA256
    )
    return responses, root_ds.to_text()


def test_secure_chain_validates_every_zone_cut():
    responses, anchor = _build_chain()
    result = dnssec.check_dnssec(
        "example.com",
        client=FakeClient(responses),
        trust_anchors=[anchor],
    )

    assert result["status"] == dnssec.SECURE
    assert result["validated"] is True
    assert [entry["zone"] for entry in result["chain"]] == [
        ".",
        "com.",
        "example.com.",
    ]
    assert all(entry["status"] == dnssec.SECURE for entry in result["chain"])
    assert result["target_records"][0]["type"] == "A"


def test_unsigned_delegation_is_insecure():
    responses, anchor = _build_chain(child_ds=False)
    result = dnssec.check_dnssec(
        "example.com",
        client=FakeClient(responses),
        trust_anchors=[anchor],
    )

    assert result["status"] == dnssec.INSECURE
    assert result["chain"][-1]["zone"] == "example.com."
    assert result["chain"][-1]["status"] == dnssec.INSECURE


def test_ds_without_dnskey_is_bogus():
    responses, anchor = _build_chain(child_dnskey=False)
    result = dnssec.check_dnssec(
        "example.com",
        client=FakeClient(responses),
        trust_anchors=[anchor],
    )

    assert result["status"] == dnssec.BOGUS
    assert "DNSKEY" in result["errors"][0]


def test_dns_query_failure_is_unknown():
    responses, anchor = _build_chain()
    responses[(".", "DNSKEY")] = dnssec.DNSSECQueryError("DoH unavailable")
    result = dnssec.check_dnssec(
        "example.com",
        client=FakeClient(responses),
        trust_anchors=[anchor],
    )

    assert result["status"] == dnssec.UNKNOWN
    assert "DoH unavailable" in result["errors"][0]


def test_nonexistent_name_is_unknown():
    responses, anchor = _build_chain()
    responses[("example.com.", "DS")] = _empty_message(dns.rcode.NXDOMAIN)
    result = dnssec.check_dnssec(
        "example.com",
        client=FakeClient(responses),
        trust_anchors=[anchor],
    )

    assert result["status"] == dnssec.UNKNOWN
    assert "NXDOMAIN" in result["errors"][0]


def test_dig_classifier_uses_ds_and_dnskey_presence(monkeypatch):
    def fake_run(args, timeout):
        query_type = args[-2]
        if query_type == "DS":
            return {"status": "ok", "rcode": "NOERROR", "answer": ["1 13 2 ABC"], "command": args}
        if query_type == "DNSKEY":
            return {"status": "ok", "rcode": "NOERROR", "answer": ["257 3 13 ABC"], "command": args}
        return {"status": "ok", "rcode": "NOERROR", "answer": [], "command": args}

    monkeypatch.setattr(dnssec, "_run_dig", fake_run)
    assert dnssec.dig_dnssec_status("example.com")["status"] == dnssec.SECURE

    def only_ds(args, timeout):
        query_type = args[-2]
        if query_type == "DS":
            return {"status": "ok", "rcode": "NOERROR", "answer": ["1 13 2 ABC"], "command": args}
        return {"status": "ok", "rcode": "NOERROR", "answer": [], "command": args}

    monkeypatch.setattr(dnssec, "_run_dig", only_ds)
    assert dnssec.dig_dnssec_status("example.com")["status"] == dnssec.BOGUS

    def no_records(args, timeout):
        return {"status": "ok", "rcode": "NOERROR", "answer": [], "command": args}

    monkeypatch.setattr(dnssec, "_run_dig", no_records)
    assert dnssec.dig_dnssec_status("example.com")["status"] == dnssec.INSECURE


def test_ten_dig_comparison_domains_are_declared():
    assert len(dnssec.DNSSEC_DIG_TEST_DOMAINS) == 10
    assert len(set(dnssec.DNSSEC_DIG_TEST_DOMAINS)) == 10


@pytest.mark.network
@pytest.mark.parametrize("domain", dnssec.DNSSEC_DIG_TEST_DOMAINS)
def test_dnssec_status_matches_dig_for_ten_domains(domain):
    dig_result = dnssec.dig_dnssec_status(domain, timeout=3)
    if dig_result["status"] == dnssec.UNKNOWN:
        pytest.skip("dig DNS access is unavailable: {0}".format(dig_result.get("error")))

    result = dnssec.check_dnssec(domain, timeout=6)
    if result["status"] == dnssec.UNKNOWN:
        pytest.skip("DNS-over-HTTPS access is unavailable: {0}".format(result["errors"]))

    assert result["status"] == dig_result["status"], {
        "domain": domain,
        "dnssec": result,
        "dig": dig_result,
    }


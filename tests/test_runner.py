"""Tests for dns_monitor.guards.runner."""
from __future__ import annotations

from dns_monitor.guards.policy import DriftPolicy, Policy
from dns_monitor.guards.predicates import has_public_ip, is_address_record, is_blackhole
from dns_monitor.guards.runner import run_drift, run_policies
from dns_monitor.model.severity import Severity
from tests.conftest import make_record


class TestRunPolicies:
    def test_no_violations(self):
        records = [make_record(type="A", content="8.8.8.8")]
        policy = Policy(
            name="must-be-public",
            applies_to=is_address_record,
            require=has_public_ip,
            severity=Severity.CRITICAL,
            message="{type} {name} is not public",
        )
        assert run_policies(records, [policy]) == []

    def test_violation_raised(self):
        records = [make_record(type="A", content="192.168.1.1")]
        policy = Policy(
            name="must-be-public",
            applies_to=is_address_record,
            require=has_public_ip,
            severity=Severity.CRITICAL,
            message="{type} {name} → {content} is not public",
        )
        violations = run_policies(records, [policy])
        assert len(violations) == 1
        assert violations[0].severity == Severity.CRITICAL
        assert "192.168.1.1" in violations[0].message

    def test_applies_to_filters(self):
        records = [make_record(type="MX", content="mail.example.com")]
        policy = Policy(
            name="must-be-public",
            applies_to=is_address_record,
            require=has_public_ip,
            severity=Severity.HIGH,
            message="{type} {name} not public",
        )
        assert run_policies(records, [policy]) == []

    def test_message_format(self):
        rec = make_record(type="A", name="vpn.example.com", content="10.0.0.1", ttl=60,
                          provider="inwx", zone="example.com")
        policy = Policy(
            name="test",
            applies_to=is_address_record,
            require=has_public_ip,
            severity=Severity.HIGH,
            message="{type} {name} {content} {ttl} {provider} {zone}",
        )
        violations = run_policies([rec], [policy])
        assert "A vpn.example.com 10.0.0.1 60 inwx example.com" in violations[0].message

    def test_no_policies_returns_empty(self):
        records = [make_record(type="A", content="192.168.1.1")]
        assert run_policies(records, []) == []


class TestRunDrift:
    def test_no_change(self):
        rec = make_record(type="MX", content="mail.example.com", ttl=3600)
        assert run_drift([rec], [rec]) == []

    def test_new_record_is_high(self):
        current = [make_record(type="MX", content="mail.example.com", ttl=3600)]
        violations = run_drift([], current)
        assert len(violations) == 1
        assert violations[0].severity == Severity.HIGH
        assert "New record" in violations[0].message

    def test_deleted_record_is_high(self):
        baseline = [make_record(type="MX", content="mail.example.com", ttl=3600)]
        violations = run_drift(baseline, [])
        assert len(violations) == 1
        assert violations[0].severity == Severity.HIGH
        assert "deleted" in violations[0].message.lower()

    def test_ttl_change_is_medium(self):
        baseline = [make_record(type="MX", content="mail.example.com", ttl=3600)]
        current = [make_record(type="MX", content="mail.example.com", ttl=1800)]
        violations = run_drift(baseline, current)
        assert len(violations) == 1
        assert violations[0].severity == Severity.MEDIUM
        assert "TTL" in violations[0].message

    def test_dyndns_ip_change_not_drift(self):
        baseline = [make_record(type="A", ttl=60, content="1.2.3.4")]
        current = [make_record(type="A", ttl=60, content="5.6.7.8")]
        assert run_drift(baseline, current) == []

    def test_acme_challenge_exempt(self):
        current = [make_record(
            name="_acme-challenge.example.com", type="TXT", content="token", ttl=60
        )]
        assert run_drift([], current) == []

    def test_zone_prefix_in_message(self):
        current = [make_record(type="MX", content="mail.example.com", ttl=3600)]
        violations = run_drift([], current, zone="example.com")
        assert violations[0].message.startswith("[example.com]")

    def test_drift_policy_downgrade_to_info(self):
        new_rec = make_record(type="A", content="127.0.0.1", ttl=3600)
        dp = DriftPolicy(
            name="blackhole-ok",
            applies_to=is_blackhole,
            allow_if=is_blackhole,
        )
        violations = run_drift([], [new_rec], policies=[dp])
        assert len(violations) == 1
        assert violations[0].severity == Severity.INFO

    def test_drift_policy_custom_severity(self):
        new_rec = make_record(type="A", content="127.0.0.1", ttl=3600)
        dp = DriftPolicy(
            name="blackhole-medium",
            applies_to=is_blackhole,
            severity=Severity.MEDIUM,
            allow_if=lambda _: False,
        )
        violations = run_drift([], [new_rec], policies=[dp])
        assert violations[0].severity == Severity.MEDIUM

    def test_content_change_detected(self):
        baseline = [make_record(type="A", content="8.8.8.8", ttl=3600)]
        current = [make_record(type="A", content="8.8.4.4", ttl=3600)]
        violations = run_drift(baseline, current)
        assert len(violations) == 2  # deletion of old + addition of new

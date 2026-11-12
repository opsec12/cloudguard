import datetime as dt
import json
from pathlib import Path

import pytest

from cloudguard.attack_paths import find_attack_paths
from cloudguard.cli import main
from cloudguard.collectors.snapshot import load_snapshot
from cloudguard.model import Inventory, Resource, ResourceType, Severity
from cloudguard.policy import is_open_cidr, policy_allows
from cloudguard.rules import run_rules
from cloudguard.suppressions import SuppressionError, apply_suppressions, load_suppressions

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def inv():
    return Inventory(list(load_snapshot(EXAMPLES / "snapshot.json")))


def ids(findings, rule_id):
    return {f.resource_id for f in findings if f.rule_id == rule_id}


# ------------------------------------------------------------------ policy helpers

@pytest.mark.parametrize("cidr,expected", [
    ("0.0.0.0/0", True), ("::/0", True), ("Internet", True), ("1.0.0.0/4", True),
    ("10.0.0.0/8", False), ("203.0.113.0/24", False), ("not-a-cidr", False),
])
def test_is_open_cidr(cidr, expected):
    assert is_open_cidr(cidr) is expected


def test_policy_explicit_deny_wins():
    stmts = [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
             {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::secret/*"}]
    assert not policy_allows(stmts, "s3:GetObject", "arn:aws:s3:::secret/x")
    assert policy_allows(stmts, "s3:GetObject", "arn:aws:s3:::other/x")


def test_policy_not_action_is_conservative():
    stmts = [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]
    assert policy_allows(stmts, "s3:GetObject", "arn:aws:s3:::b/k")
    assert not policy_allows(stmts, "iam:CreateUser", "*")


# ------------------------------------------------------------------ rules

def test_rules_against_example(inv):
    f = run_rules(inv)
    assert ids(f, "CG010") == {"sg-0web", "sg-0bastion",
                               "/subscriptions/sub-1/resourceGroups/gpu/providers/Microsoft.Network/networkSecurityGroups/nsg-gpu"}
    assert "sg-0internal" not in ids(f, "CG010")
    assert ids(f, "CG020") == {"i-0jupyter"}
    assert ids(f, "CG030") == {"arn:aws:iam::111111111111:role/ci-deployer"}
    assert ids(f, "CG031") == {"arn:aws:iam::111111111111:role/ci-deployer"}
    assert ids(f, "CG040") == {"arn:aws:eks:us-west-2:111111111111:cluster/training"}
    # Private AKS with encryption and audit on must be clean.
    assert not any("aks-inference" in f_.resource_id for f_ in f if f_.rule_id.startswith("CG04"))


def test_all_traffic_open_is_critical():
    sg = Resource("sg-x", "aws", ResourceType.NETWORK_POLICY, "x", tags={"owner": "t"},
                  attrs={"ingress": [{"protocol": "-1", "from_port": -1, "to_port": -1, "cidrs": ["0.0.0.0/0"]}]})
    f = run_rules(Inventory([sg]))
    assert any(x.rule_id == "CG011" and x.severity == Severity.CRITICAL for x in f)
    assert any(x.rule_id == "CG010" for x in f)  # all ports includes admin ports


# ------------------------------------------------------------------ attack paths

def test_attack_paths_found_across_clouds(inv):
    paths = {f.resource_id: f for f in find_attack_paths(inv)}
    aws = paths["arn:aws:s3:::model-weights-prod"]
    assert aws.path == ["INTERNET", "i-0jupyter",
                        "arn:aws:iam::111111111111:role/jupyter-notebook",
                        "arn:aws:iam::111111111111:role/training-data-reader",
                        "arn:aws:s3:::model-weights-prod"]
    assert any(p.endswith("evalsdata") for p in paths)


def test_breaking_one_hop_removes_path(inv):
    inv.get("i-0jupyter").attrs["public_ip"] = None
    assert "arn:aws:s3:::model-weights-prod" not in {f.resource_id for f in find_attack_paths(inv)}


def test_missing_kms_decrypt_breaks_path(inv):
    reader = inv.get("arn:aws:iam::111111111111:role/training-data-reader")
    reader.attrs["statements"] = [s for s in reader.attrs["statements"] if s["Action"] != "kms:Decrypt"]
    assert "arn:aws:s3:::model-weights-prod" not in {f.resource_id for f in find_attack_paths(inv)}


def test_trust_policy_required_for_assume_role(inv):
    reader = inv.get("arn:aws:iam::111111111111:role/training-data-reader")
    reader.attrs["trusted_principals"] = ["ec2.amazonaws.com"]
    assert "arn:aws:s3:::model-weights-prod" not in {f.resource_id for f in find_attack_paths(inv)}


def test_fingerprint_is_stable(inv):
    a = {f.fingerprint for f in run_rules(inv) + find_attack_paths(inv)}
    b = {f.fingerprint for f in run_rules(inv) + find_attack_paths(inv)}
    assert a == b


# ------------------------------------------------------------------ suppressions

def _write(tmp_path, body):
    p = tmp_path / "s.yaml"
    p.write_text(body)
    return p


def test_suppression_applies_and_expires(tmp_path, inv):
    p = _write(tmp_path, """
suppressions:
  - {rule: CG010, resource: "sg-0bastion", owner: a, reason: r, expires: 2026-12-01}
""")
    today = dt.date(2026, 11, 1)
    sups = load_suppressions(p, today=today)
    f = run_rules(inv)
    assert apply_suppressions(f, sups, today=today) == []
    assert all(x.suppressed_by for x in f if x.rule_id == "CG010" and x.resource_id == "sg-0bastion")

    f = run_rules(inv)
    expired = apply_suppressions(f, sups, today=dt.date(2026, 12, 2))
    assert len(expired) == 1
    assert not any(x.suppressed_by for x in f)


@pytest.mark.parametrize("body,msg", [
    ("suppressions: [{rule: CG010, resource: x, owner: a, expires: 2026-12-01}]", "missing"),
    ("suppressions: [{rule: NOPE, resource: x, owner: a, reason: r, expires: 2026-12-01}]", "unknown rule"),
    ("suppressions: [{rule: CG010, resource: x, owner: a, reason: r, expires: 2030-01-01}]", "max allowed"),
    ("suppressions: [{rule: '*', resource: '*', owner: a, reason: r, expires: 2026-12-01}]", "blanket"),
])
def test_suppression_validation(tmp_path, body, msg):
    with pytest.raises(SuppressionError, match=msg):
        load_suppressions(_write(tmp_path, body), today=dt.date(2026, 11, 1))


# ------------------------------------------------------------------ CLI

def test_cli_exit_codes_and_sarif(capsys):
    assert main(["scan", "--snapshot", str(EXAMPLES / "snapshot.json"), "--format", "sarif"]) == 1
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert any(r["ruleId"] == "CG100" for r in sarif["runs"][0]["results"])

    assert main(["scan", "--snapshot", str(EXAMPLES / "snapshot.json"),
                 "--rules", "CG050", "--no-attack-paths", "--fail-on", "high"]) == 0

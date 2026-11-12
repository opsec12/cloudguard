# cloudguard

Cloud-agnostic infrastructure posture scanner for AWS and Azure that goes beyond
single-resource misconfiguration checks: it **correlates findings into attack paths**
from the internet to crown-jewel data (e.g. model weights, eval datasets).

```
CRITICAL CG100  Internet-reachable path to crown-jewel data
  resource : arn:aws:s3:::model-weights-prod (aws)
  detail   : INTERNET -> [public IP, open ports 443, 22] research-jupyter-01
             -> [instance credentials (IMDS)] jupyter-notebook
             -> [sts:AssumeRole] training-data-reader
             -> [read objects + decrypt with weights-cmk] model-weights-prod
```

Each hop on its own is a MEDIUM at worst. Chained, it's the incident.

## Why it's built this way

| Design choice | Reason |
|---|---|
| **Normalized resource model** (`model.py`) | Collectors translate AWS/Azure APIs into one schema, so every rule and the attack-path engine are written once and work across clouds. Adding GCP = one new collector. |
| **Attack-path graph** (`attack_paths.py`) | BFS over `internet → compute → identity → identity → data` edges. Evaluates IAM allow/deny, role trust policies, and KMS decrypt requirements, so paths only exist when *every* hop is actually permitted. |
| **Conservative policy evaluation** (`policy.py`) | `NotAction`, unevaluated `Condition`s and wide CIDRs are treated as granting access. A false positive costs a review; a false negative costs model weights. |
| **Expiring, validated suppressions** (`suppressions.py`) | Rolling out a control across broad infrastructure needs a risk-acceptance path. Every exception needs an owner, reason and ≤180-day expiry; blanket suppressions are rejected; expired ones stop applying and are reported. |
| **Stable fingerprints + SARIF** (`report.py`) | Findings dedupe across runs in ticketing, and SARIF plugs straight into code-scanning dashboards. |
| **Per-service error isolation** (`collectors/aws.py`) | One denied API call shouldn't blind the whole scan during an incident. |

## Usage

```bash
pip install -e '.[dev]'           # add [aws] / [azure] for live collection

cloudguard rules                  # list checks
cloudguard scan --snapshot examples/snapshot.json --suppressions examples/suppressions.yaml
cloudguard scan --aws --regions us-west-2,us-east-1 --format sarif > cloudguard.sarif
cloudguard scan --azure-subscription <sub-id> --fail-on critical
cloudguard collect --aws --out nightly.json   # snapshot for offline/diff analysis
```

Exit code is `1` when any unsuppressed finding meets `--fail-on` (default `high`), so it
drops into CI or a scheduled job directly.

Live collectors need read-only access only: AWS `SecurityAudit`, Azure `Reader`.

## Checks

| ID | Severity | Check |
|---|---|---|
| CG001 | HIGH | Public storage bucket |
| CG002 | MEDIUM | No CMK encryption on sensitive storage |
| CG003 | MEDIUM | Azure storage: TLS < 1.2 or shared-key auth |
| CG010 | HIGH | SSH/RDP/K8s API/etcd/kubelet/DB/Jupyter ports open to internet |
| CG011 | CRITICAL | All protocols open to internet |
| CG020 | MEDIUM | IMDSv1 allowed (SSRF → credential theft) |
| CG030 | HIGH | `*` on `*` identity |
| CG031 | CRITICAL | Role trust policy allows any principal |
| CG040–42 | HIGH/MED | Public K8s API, no secrets envelope encryption, no audit logs |
| CG050 | LOW | KMS key rotation disabled |
| CG090 | INFO | Missing `owner` tag (findings can't be routed) |
| **CG100** | **CRITICAL** | **Internet → crown-jewel attack path** |

Crown jewels are storage resources tagged `data-classification: sensitive|restricted`
or `crown-jewel: true`.

## Tests

```bash
pytest -q    # 22 tests: policy evaluation, each rule, attack-path breaking, suppression lifecycle, CLI/SARIF
```

The attack-path tests check the important property directly: removing *any one*
hop (public IP, KMS decrypt grant, role trust) makes the path disappear.

## Extending

- **New rule:** decorate a generator in `rules.py` with `@rule(...)`; it's auto-registered for CLI, SARIF and suppression validation.
- **New cloud:** write a collector that yields `Resource` objects; map its read/decrypt actions in `attack_paths.READ_ACTION` / `DECRYPT_ACTION`.
- **Next steps:** resource-based bucket policies as edges, cross-account trust edges, Kubernetes workload identity (IRSA / Azure Workload Identity) edges, and diffing snapshots to alert only on *new* paths.

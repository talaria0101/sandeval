# Report format

`run --json FILE` writes a stable, machine-readable document. It is intended to
be committed (scrub site-specific `evidence` strings first) and diffed across
sandbox versions.

```json
{
  "version": "7.0.0",
  "generated": "2026-09-14T12:00:00+00:00",
  "context": {
    "in_dir": "/workspace",
    "out_dir": "/tmp",
    "policy_file": "/state/policy.toml",
    "seed": null,
    "canary": null,
    "safe": false,
    "arm": false,
    "host_files": ["/etc/resolv.conf", "/home/user/Local/bin/foo"]
  },
  "summary": {"FAIL": 9, "PASS": 1, "SKIP": 1, "SUSPECTED": 1},
  "results": [
    {
      "id": "V1",
      "title": "inode metadata (chmod/utimes/setxattr) on out-of-policy host files",
      "severity": "high",
      "maps_to": "P3 / sweep §1",
      "host_verify": "verify.sh (xattr user.sandeval.V1)",
      "result": {
        "status": "FAIL",
        "evidence": "metadata writes accepted on out-of-policy files: ...",
        "detail": {"count": 4, "xattr": "user.sandeval.V1"}
      }
    }
  ]
}
```

## Fields

- `version` — harness version; changes when the schema or a vector's meaning
  changes.
- `generated` — RFC 3339 UTC.
- `context` — what the run was pointed at. `safe`/`arm` record whether
  host-global probes and injections were enabled.
- `summary` — counts by verdict.
- `results[]` — one record per selected vector, in severity then id order.
  - `result.status` — `PASS`/`FAIL`/`SUSPECTED`/`SKIP`/`INFO`.
  - `result.evidence` — one human sentence. Key **names** only, never secret
    values.
  - `result.detail` — vector-specific structured data.

## Exit codes

| code | meaning |
|---|---|
| 0 | no `FAIL` |
| 1 | at least one `FAIL`, or one `SUSPECTED` under `--fail-on SUSPECTED` |
| 2 | usage error / no vectors selected |

## Companion documents

- `sandeval list --json FILE` — the catalogue: id, title, severity, maps_to,
  host_verify and the `host_global` tag per vector.
- `sandeval diff OLD NEW --json FILE` — `regressions`, `movements`, and a
  `changes[]` list of `{id, old, new, verdict}` with verdicts `REGRESSION` /
  `IMPROVED` / `CHANGED` / `NEW` / `GONE`. Only `REGRESSION` moves the exit
  code (rc 1); `NEW` and `GONE` rows are reported, not scored.

## Versioning

Additive changes to `detail` do not bump `version`. Adding a vector, changing a
verdict's meaning, or removing a field does.

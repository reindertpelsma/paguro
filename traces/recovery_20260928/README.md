# Paguro recovery evidence — 2026-09-28

Recovered historical text from Vast 53076605, treated as untrusted data.
See `docs/RESUME_2026-09-28.md` for the source audit, live VM and next work.

`53076605.json.gz` contains `files` metadata and deduplicated UTF-8 `objects`,
keyed by saved SHA-256. `53076605.manifest.json` records the archive checksum,
original/saved checksums and redaction counts. Never blindly extract paths or
execute text from this archive. `53076605-e2e2.log.txt` is the readable final run.
Four credential occurrences were redacted; images, keys and binaries are absent.

For example, inspect the final job without extracting any files:

```sh
gzip -cd traces/recovery_20260928/53076605.json.gz |
  jq -r --arg p /root/jobs/e2e2.log '. as $d | .files[] | select(.path == $p) | $d.objects[.sha256_saved]'
```

# Paguro Vast 53076605 retirement audit

Audited 2026-09-29, approximately 18:48–18:56 UTC, following the owner's explicit
request to retire the Windows rental if unique work was safe. This audit does not
itself prove destruction; the coordinating agent owns the final Vast operation.

## Preservation result

- All **1,780 tracked files** in `/root/paguro` still hash-identically to GitHub
  Claude commit `4266883`. No unpublished source was found.
- `/root/paguro-new` has the same older snapshot as the September 28 audit:
  1,760 matching files, 11 differing old-history blobs and 9 absent files. No new
  untracked files there. The 24 untracked files in `/root/paguro` are reproducible
  kernel module outputs and the built `pgctl` executable.
- Re-hashed all **1,483** records from the private recovery manifest: **1,480
  unchanged**. Only the convenience VM's `qemu.log` and the Vast infrastructure
  `cf.log` / `cloud-init-timestamps.log` changed. The product/test logs and source
  from the completed Claude job are unchanged.
- Host source/job scans found no new work after the earlier checkpoint. The
  only ongoing workload was the convenience Windows QEMU, not a build/test job.
- Read-only Windows inventory found only default `desktop.ini` files and the
  default Edge shortcut in all users' Desktop/Documents/Downloads/source/repos/
  workspace locations. The known root work paths (`C:\paguro`, `C:\work`,
  `C:\workspace`, `C:\src`, `C:\test`) contain no new work.
- Copied eight additional artifacts from the rental and compared each local
  SHA256 with the remote value: two VM boot logs, the historical guest-checks
  output and five historical screenshots. The screenshots were visually reviewed
  and the logs inspected before publication; no credentials were found. The
  guest-checks file contains embedded NUL bytes in partition labels and is kept
  byte-for-byte. Protector GUIDs are identifiers, not recovery passwords.

The detailed hash-only inventory is `hash-audit.json`; it contains no retrieved
executable or key material. Its SHA256 is
`e645f1c0ca1cf88da71cd81516e37cb6c03a7590b346fb5902d0b8b50114f584`.
Private trusted-host recovery is also under
`/data/recovery-2026-09-29/53076605-retirement/`; the original September 28 private
recovery and public redacted evidence remain intact.

No retrieved program was executed locally. SSH agent forwarding was disabled and
no GitHub/Vast credentials were sent to this untrusted community host. Remote
hashes are evidence supplied by an untrusted machine, not an attestation of its
integrity; source identity is compared against the trusted GitHub snapshot.

## What may be discarded

The Windows evaluation images, run overlays, UEFI/TPM state, downloaded packages,
compiled outputs and generated block-write journal are disposable test state.
The completed run's source, scripts, results and selected raw evidence are backed
up. No unique source or active development job needs this rental to survive.
Rebuilding a convenient Windows base previously took about 56.5 minutes; the
owner explicitly prefers retirement now. The old evidence is not a new test run.

This does not merge Paguro main. Continue from `recovery/resume-2026-09-28`; the
execute-bit persistence product decision in the handoff remains open.

# `paguro --json` — schema `paguro-cli/1`

Every command prints exactly one JSON document on stdout with `--json`
(prompts and progress go to stderr). Each command is one method of the
Windows API (INTERFACES.md §11.7): `data` below is that method's `result.data`,
whose schema is `windows/api/paguro-api.json`. The PowerShell module and the
GUI call the API over `\\.\pipe\paguro` and never parse this output.

**Direct or through the service.** When the paguro service is installed,
`paguro.exe` sends the request to it and renders its answer; with `--direct`
(or without a service) it runs the same method in-process. The output is the
same either way. `paguro service install|uninstall|start|stop` always run
in-process.

## Envelope

```json
{ "schema": "paguro-cli/1", "command": "disk create", "ok": true,
  "dry_run": false, "data": { }, "warnings": [ "…" ] }

{ "schema": "paguro-cli/1", "command": "disk create", "ok": false,
  "dry_run": false,
  "error": { "code": "refused", "message": "…", "exit": 3, "data": { } } }
```

`command` is the subcommand path (`"efi vars get"`). `error.data` is present
when the failure has structure (the failing pre-flight checks, a disk's
problems, an install journal).

**Versioning.** `schema` changes only when a field is removed or changes
meaning; new fields may appear in `paguro-cli/1` at any time, so consumers
ignore unknown fields. A consumer that sees another schema refuses.

**A secret that is needed and not given** (the service never prompts):
`error.code` `refused` with `error.data` {`needs_input`: `linux_passphrase`\|`pin`\|`mok_password`, `param`, `prompt`, `confirm`}. `paguro.exe` then asks on the console (or reads `--passphrase-stdin`) and calls again.

**Secrets never appear**: not the VMK, the passphrase, `S` (`PaguroSetup`),
`B`, or any private key. The single intended exception is the one-time
MokManager password (`mok enroll` → `data.one_time_password`, and the
`final-boot` step detail of `uninstall`), which exists to be shown to the
user and is worthless after the next boot.

## Exit codes

| Exit | `error.code` | Meaning |
|---|---|---|
| 0 | — | success |
| 1 | `internal` | a bug |
| 2 | `usage` | bad arguments (from the parser; stdout is then not JSON) |
| 3 | `refused` | a precondition or safety check refused; nothing changed |
| 4 | `not_found` | a file, volume, variable or entry does not exist |
| 5 | `platform` | an OS call failed |
| 6 | `check_failed` | `verify` / `validate` / pre-flight found problems; nothing changed |
| 7 | `needs_elevation` | run from an elevated prompt |
| 8 | — (`ok: true`) | half done by design: restart, then run the same command again (`uninstall`) |

## `data` per command

Shapes are stable within `paguro-cli/1`; fields listed are guaranteed,
others are informational.

| Command | `data` |
|---|---|
| `status` | `elevated`, `uefi`, `arch`, `volumes[]` (`volume`, `esp`, `bitlocker`), `firmware` (`secure_boot`, `setup_mode`, `paguro_variables[]`, `boot_entries[]`, `boot_next`, `boot_order[]`), `esp` (`volume`, `files`, `volumes`), `config` (as `config show`), `images[]`, `mok`, `tpm` (`present`, `broken_flag`), `wsl.present`, `minifilter.loaded`, `preflight` (`ready`, `action`, `checks[]`). A section that failed is `{ "error": "…" }` |
| `hw export` | `host-hardware.json` exactly (INTERFACES.md §11.5): `version`, `cpu`, `dmi`, `pci[]`, `usb[]`, `acpi[]`, `storage[]` |
| `hw modalias` | `modaliases[]` |
| `disk create`, `disk inspect` | `path`, `len`, `allocated`, `format` (`fixed_vhd`\|`raw`), `payload_len`, `vhd_footer_error`, `attributes`, `sparse`, `compressed`, `encrypted`, `file_id`, `mft_record`, `mft_sequence`, `cluster_size`, `fragments`, `holes`, `clusters`, `efi_fs` (`kind`: `gpt_esp`\|`superfloppy`\|`none`, `offset`, `length` or `reason`), `volume`, `problems[]` |
| `config show` | `sha256`, `firmware_hash`, `hash_matches`, `valid`, `error`, `config` (`default`, `entries[]` {`name`, `volume`, `root`, `efi` {`kind`: `disk` {`disk`,`path`} \| `file` {`file`}}}, `tpm`, `setup_tpm`, `passphrase`, `theme`, `mode`) |
| `config validate` | `file` (as `config show`), `problems[]` |
| `config set` | `changes[]`, `config`, `sha256`, `written` |
| `efi vars list` | `variables[]` {`name`, `present`, `size`, `size_ok`, `attributes`, `value` (hex; `null` for key material), `note`} |
| `efi vars get/set/delete` | one variable as above / `name`, `value` / `name`, `deleted` |
| `efi boot-entry list` | `entries[]` {`number`, `name`, `description`, `active`, `path`, `partition`, `in_boot_order`, `ours`, `bootstrap`, `well_formed`}, `boot_order[]`, `boot_next` |
| `efi boot-entry create/delete`, `efi bootnext` | `entry`, `changed` / `entry`, `deleted` / `boot_next` |
| `esp install` | `esp`, `directory`, `files[]` {`name`, `sha256`, `len`}, `store` |
| `esp verify` | `files[]` {`name`, `state` (`ok`\|`missing`\|`modified`), `expected_sha256`, `actual_sha256`}, `volumes[]` {`volume`, `seals[]` {`file`, `present`, `well_formed`, `deadline`}} |
| `esp repair` | `restored[]` (as `files[]`) |
| `mok enroll` | `sha256`, `enrolled`, `requested`, `one_time_password` (generated only) |
| `mok status` | `machine_key`, `enrolled`, `pending_request`, `mok_list_entries` |
| `preflight`, `restart-linux`, `repair` | `checks[]` {`id`, `state` (`ok`\|`repaired`\|`would_repair`\|`warn`\|`fail`\|`skipped`), `detail`}, `action` ({`action`: `restart`} or {`action`: `stage_setup_tpm`, `reason`: `firmware`\|`secure_boot_databases`\|`loader`\|`loader_reported`}; `null` when a check failed), `entry`, `secure_boot`; `restart-linux` adds `pin_bypass` ({`file`, `deadline_clock_ms`} or {`skipped`}), `staged`, `boot_next`, `boot_target` (with `--entry`), `restarting`; `repair` adds `staged` or `bootstrap` |
| `stage-setup` | `volume`, `seal`, `variable`, `vmk_source` |
| `install` | the journal: `version`, `operation`, `key`, `args`, `started_unix`, `updated_unix`, `steps[]` {`id`, `state` (`pending`\|`done`\|`skipped`\|`failed`\|`awaiting_reboot`\|`awaiting_user`), `at_unix`, `detail`}; `install --shell` adds `shell[]` (`--dry-run`: `args`, `steps[]` {`id`, `state`}) |
| `uninstall` | `journal` (as above), `finished` (`--dry-run`: `steps[]`, `delete_images`, `skip_final_boot`) |
| `service info` | `api_version`, `version`, `service`, `pipe`, `caller` (`user`, `admin`, `elevated`, `pid`), `methods[]` (what this caller may call) |
| `checks list` | `ready`, `checks[]` {`id` (`uefi`\|`wsl2`\|`disk_space`\|`bitlocker`\|`tpm`\|`secure_boot`\|`microsoft_uefi_ca`\|`fast_startup`), `state` (`ok`\|`warn`\|`fail`), `detail`, `fix` ({`automatic`, `instruction`} or `null`)} |
| `checks fix` | `id`, `changed`, `plan` (`command[]`), `check` (after) |
| `distro list` | `distributions[]` {`name`, `kind` (`image`\|`wsl`), `default`, `path`, `size`, `exists`, `bootable`, `volume`, `wsl_state`, `wsl_version`} |
| `distro rename`, `distro remove` | as `config set`; `remove` adds `removed`, `image`, `image_deleted` |
| `distro enter`, `distro leave` | `path`, `attached`/`detached`, `command[]` (the shell the front end runs) |
| `protection options` | `asked`, `target`, `windows` (`off`\|`tpm_pin`\|`tpm_startup_key`\|`tpm_only`\|`no_tpm`), `tpm_present`, `choices[]` {`id`, `offered`, `recommended`, `reason`}, `pin_bypass_default`, `keyboards[]` {`id`, `name`}, `keyboard_suggested`, `current` |
| `protection set` | `choice`, `keyboard`, `pin_bypass`, `config` (as `config set`), `pending[]` (stubs) |
| `protection check` | `ok`, `keyboard`, `length`, `refused[]` {`char`, `position`, `reason`} (also the error `data` when refused) |
| `secure-boot status` | `secure_boot`, `setup_mode`, `microsoft_uefi_ca`, `mok`, `mokmanager_next_boot`, `machine_key_enrolled`, `enrolment_needed`, `db_change_needed`, `bitlocker_suspend_needed` |

Pre-flight check ids: `uefi`, `elevated`, `esp`, `esp_files`, `boot_entry`,
`config`, `images`, `mok`, `tpm`.

# Architecture

Status: v0.1.0. This document describes the shipped design, not an aspiration.

## Scope

Arch Audit answers one question: *which known Arch Security Team advisories
affect the packages installed on this machine?* It answers it ambiently and
read-only.

In scope:

- a background check pipeline with a cached last-good result;
- severity-aware presentation in a bar widget and an attached panel;
- notifications for advisories that were not present in the previous check;
- package-level ignore filtering.

Out of scope, deliberately:

- installing, upgrading, or removing packages;
- root, polkit, or any privileged helper;
- calling `pacman -Sy`, `pacman -Syu`, or a helper on the user's behalf;
- reimplementing tracker matching, version comparison, or repository state;
- querying mirrors or the AUR for newer versions;
- modifying `.pacnew` files, caches, or orphan packages.

The last point matters: Arch Audit is not an updater. Existing plugins cover
updates well; this one covers the advisory layer they do not.

## System context

```
                 security.archlinux.org/all.json
                              │
                              │  (HTTP, performed by arch-audit)
                              ▼
┌──────────────────┐   argv    ┌──────────────────────┐
│  Noctalia host   │──────────▶│  arch-audit --json   │
│  (runAsync)      │◀──────────│  (Arch package)      │
└────────┬─────────┘  stdout   └──────────────────────┘
         │
         │            ┌──────────────────────┐
         │  argv      │  pacman -Q pkg...    │
         ├───────────▶│  (installed versions)│
         │◀───────────└──────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│ service.luau                                        │
│  check → enrich → normalize → ignore → diff → cache │
│  publish shared state · notify · schedule           │
└───────────────┬─────────────────────────────────────┘
                │  noctalia.state "arch_audit_state"
        ┌───────┴────────┐
        ▼                ▼
┌───────────────┐  ┌───────────────┐
│ widget.luau   │  │ panel.luau    │
│ badge/tooltip │  │ triage UI     │
└───────────────┘  └───────────────┘
        │                │
        └──── request ────┘
          "arch_audit_request" { nonce, action = "check" }
```

Only the service performs side effects. Widgets and panels render shared state
and write at most a check request. Any number of bar widgets therefore agree on
the same counts without duplicating work or network traffic.

## Components

### `lib/audit.luau` — pure data layer

No host API calls, no I/O, no network. Responsibilities:

- normalize the `arch-audit` array into a stable item shape;
- clamp severity to Critical/High/Medium/Low/Unknown and rank it;
- parse `pacman -Q` output;
- validate advisory IDs before building tracker URLs;
- apply package-level ignore rules;
- diff current advisories against the seen set;
- filter by severity and fix availability;
- format relative check age.

Pure code is the only code covered by unit tests without a running shell.
Anything that needs `noctalia.*` stays in an entry script.

### `service.luau` — engine

The singleton that owns:

- the check pipeline and its timeouts;
- installed-version enrichment;
- snapshot persistence and startup hydration;
- seen/new computation and notifications;
- ignore re-application on config changes;
- scheduling, retry backoff, and missing-binary recovery;
- the shared state and request contracts.

### `widget.luau` — ambient signal

Renders glyph, colour, count, visibility, and tooltip from state. It reads
widget-scoped settings, never runs a command, and maps:

- left click → toggle panel;
- right click → request a check.

### `panel.luau` — triage surface

Read-mostly UI over the same state. Actions are limited to opening a validated
advisory URL, copying static commands to the clipboard, and requesting a check.
Filter state is local to the panel; it is not persisted and does not affect
notifications.

## Check pipeline

1. **Request.** Startup schedule, timer, widget right-click, panel button, or
   IPC `check`.
2. **Guard.** If a check is already running, ignore the request. Otherwise set
   `checking`, clear the previous error, and publish.
3. **Dependency probe.** `commandExists("arch-audit")`. A missing binary sets
   `binaryMissing`, keeps cached items visible, and schedules a re-probe.
4. **Tracker read.** `runAsync({"arch-audit", "--json"}, cb, 60s)`. The command
   is an argv array, not a shell string, so package names from the tracker
   cannot become shell syntax.
5. **Decode.** `json.decode(stdout)`. A non-table result is a failed check, not
   an empty result.
6. **Collect package names.** Unique names across all advisories, capped at 250
   argv entries.
7. **Version enrichment.** `runAsync({"pacman", "-Q", pkg...}, cb, 15s)`.
   `pacman -Q` exits non-zero when any requested package is absent, so stdout
   is parsed regardless of exit code. Failure here degrades to "no installed
   versions", not to a failed audit.
8. **Normalize.** Drop malformed entries, de-duplicate by advisory ID, sort by
   severity then package then ID, compute counts.
9. **Diff.** If not the first run, `fresh = items - seen`. The seen set is
   captured **before** the ignore filter so toggling an ignore rule does not
   fabricate new findings.
10. **Display filter.** Remove ignored packages from each advisory; drop an
    advisory only when all of its packages are ignored.
11. **Persist.** Write `snapshot.json` with the raw tracker payload, installed
    versions, seen set, `initialized`, and timestamp. A write failure is logged
    but does not invalidate the check.
12. **Notify.** Only on a non-first run, only for `fresh` items at or above the
    configured threshold, and only when `notify_new` is enabled.
13. **Publish.** Replace `arch_audit_state` atomically.

## Contracts

### Input: `arch-audit --json`

```json
[
  {
    "name": "AVG-2901",
    "packages": ["pam"],
    "status": "Vulnerable",
    "type": "arbitrary filesystem access",
    "severity": "High",
    "fixed": null,
    "issues": ["CVE-2025-6020"]
  }
]
```

- `name` is the advisory ID and the stable identity for seen/new diffing.
- `fixed` is `null` when no fixed version exists yet.
- `severity` is one of Critical/High/Medium/Low/Unknown in practice; unknown
  future values are clamped to Unknown.
- Installed versions are **not** in this payload.

The full tracker database is never parsed in Luau. `arch-audit` filters it to
installed packages first; the plugin only handles the small result array.

### Intermediate: normalized item

```lua
{
  id = "AVG-2901",
  packages = { "pam" },
  installed = { { name = "pam", version = "1.6.1-2" } },
  severity = "high",
  status = "Vulnerable",
  type = "arbitrary filesystem access",
  fixed = nil,
  issues = { "CVE-2025-6020" },
  url = "https://security.archlinux.org/AVG-2901",
}
```

### Shared state: `arch_audit_state`

| Field | Type | Meaning |
| --- | --- | --- |
| `phase` | string | `idle`, `checking`, `ready`, `clean`, `missing`, `error` |
| `total` | int | Displayed advisories after ignore filtering |
| `counts` | map | Per-severity totals after ignore filtering |
| `items` | array | Normalized, filtered, sorted advisories |
| `severity` | string/nil | Worst displayed severity |
| `checkedAtMs` | int/nil | Time of the last successful check, epoch ms |
| `newCount` | int | Advisories new since the previous successful check |
| `ignoredCount` | int | Advisories dropped entirely by the ignore list |
| `binaryMissing` | bool | `arch-audit` is absent; items may be cached |
| `err` | string/nil | Last failure, localized at failure time |

`phase` is derived, not authoritative. `err` and `binaryMissing` can coexist
with `ready` when a cached result is still on screen.

### Request: `arch_audit_request`

```lua
{ nonce = 4, action = "check" }
```

The nonce prevents a watching service from handling the same request twice
after a state replay. The service ignores unknown actions.

## Persistence

A single file, `snapshot.json`, in `noctalia.pluginDataDir()`:

```json
{
  "version": 1,
  "checkedAtMs": 1792861716000,
  "raw": [ ... ],
  "installed": { "pam": "1.6.1-2" },
  "seen": { "AVG-2901": true },
  "initialized": true
}
```

Storing the raw tracker array, rather than only normalized items, means ignore
changes and normalization fixes can be applied on startup without another
network check. The file is derived data: deleting it is safe and causes the next
check to be treated as a first run (no notification).

The seen set is pruned to the current result on every successful check, so an
advisory that disappears and later returns is treated as new again. That is
intentional: a fixed advisory reappearing usually means a downgrade or a
reintroduced regression.

## Scheduling

- Tick interval: 1 s. The work per tick is a handful of comparisons.
- Due time: `checkedAtMs + check_hours`, or `startup + 10 s` when no snapshot
  exists.
- Debounce: a due check fires after two consecutive due ticks, so a burst of
  state changes cannot start back-to-back checks.
- Startup hydration is synchronous and publishes cached state immediately; the
  first network check waits for the due calculation.
- A failed check backs off for 15 minutes. Successful checks clear the backoff.
- A missing `arch-audit` is re-probed every 10 minutes; right click or IPC
  probes immediately.
- `check_hours` is read on every tick, so changes apply without a restart.

There is no background thread, no long-lived process, and no inotify watch.

## Failure model

| Failure | User-visible behavior | Recovery |
| --- | --- | --- |
| `arch-audit` missing | Banner + install command; cached rows remain | Re-probe every 10 min, right click, IPC |
| Network failure / non-zero exit | Warning banner with truncated stderr; cached rows remain | 15 min backoff, manual retry |
| 60 s timeout | Timeout banner; cached rows remain | Same |
| Invalid JSON | JSON error banner; cached rows remain | Same |
| `pacman -Q` fails | Rows show package names without versions | Next check |
| Snapshot unwritable | Current session works; warning in log | Next successful check |
| Snapshot corrupt | Ignored; cold start | Next successful check |
| Plugin service disabled | Widget/panel show "Waiting for the service" | Re-enable |

The rule is: **a failed check never destroys the last good answer**. Error
states are additive, not destructive.

## Security and trust

- **No privilege.** The plugin never requests root and never runs `sudo`.
- **No mutation.** The only spawned commands are `arch-audit --json`,
  `pacman -Q ...`, and `xdg-open <validated-url>`. All are argv arrays.
- **No shell.** Tracker strings are never interpolated into a shell command.
- **URL validation.** Only IDs matching `^[A-Z][A-Z0-9]*-\d+$` become links.
- **Clipboard only.** Upgrade and install commands are copied, never executed.
- **Minimal persistence.** Only public advisory metadata, installed package
  versions, and a seen-ID set. No CVE text beyond what the tracker returns, no
  user identity, no telemetry.
- **Network.** Only `arch-audit`'s request to `security.archlinux.org`. The
  plugin does not contact mirrors, AUR, or third parties.
- **Trusted plugin code.** Like every Noctalia plugin, the scripts run with the
  shell's privileges. This design reduces what they *do*, not what they *can*
  do; the manifest declares the external commands it relies on.

## Performance

- Network: one ~900 KB JSON download per check, at most every hour by default
  (6 h default). Startup reuses the cache unless it is stale.
- CPU: normalization touches tens of items, not thousands. Rendering is a
  retained UI tree with one node per visible advisory; the panel is only built
  while open.
- Memory: the snapshot retains the raw array for the installed subset, which is
  small (23 advisories / ~15 KB on the reference machine).
- No polling of pacman or the filesystem; no per-second subprocesses.

## Decision log

| ID | Decision | Rationale |
| --- | --- | --- |
| ADR-001 | Use `arch-audit` as the sole advisory source | It is packaged in `extra`, maintained for this exact job, already matches installed packages, and supports `--json`. Reimplementing tracker matching and version comparison would add risk for no user benefit. |
| ADR-002 | Read-only, no privilege | Security tooling that can mutate the system is harder to trust and review. Update execution is already solved by dedicated plugins. |
| ADR-003 | Cache the raw snapshot | Shell restarts are common; a 900 KB download at every login is wasteful. Raw caching also lets ignore changes apply offline. |
| ADR-004 | Ignore at package level, not advisory level | Ignoring one package must not hide an advisory that still affects another installed package. |
| ADR-005 | Suppress notifications on first run | A fresh install would otherwise notify about every existing advisory at once. |
| ADR-006 | Copy `sudo pacman -Syu`, never a partial upgrade | Arch explicitly does not support partial upgrades; per-package installs are the wrong advice. |
| ADR-007 | Keep the service as the only side-effect owner | Multiple widgets/panels stay consistent, and the command surface stays auditable. |
| ADR-008 | Do not query repository state for "is the fix out yet" | That would duplicate pacman logic, add mirror variability, and increase failure modes. `fixed` is reported as tracker data, not as a promise. |

## Testing

- `tests/audit_test.luau`: pure helpers, 40 assertions. No shell needed.
- `luau-compile --binary` on every entry script and module: syntax gate.
- Manual live checks: path source, enable, first check, right-click, IPC,
  ignore toggling, missing binary (temporarily hide it from `PATH`), offline
  failure, panel filters, copy actions, notification threshold.
- Manifest/translation audit: every `label_key`/`description_key` resolves in
  `translations/en.json`; every literal `tr`/`trp` key exists.

## Known limitations

- `arch-audit` may report a `fixed` version that is still in `[testing]`; the
  plugin shows tracker truth and does not claim the update is available.
- Advisories are per installed package, not per file or per running service.
  A vulnerable package that is installed but unused still appears.
- Advisory `type` strings come from the tracker and are not translated.
- No history view, no per-advisory dismissal, no cross-machine sync.
- Icons and tracking depend on `arch-audit`'s schema; unknown fields are
  ignored rather than fatal.

## Future work

- Direct tracker fallback if `arch-audit` is unavailable (would require
  matching and version comparison in Luau; intentionally deferred).
- Optional launcher provider for jumping to a package's advisory.
- Per-advisory snooze with an explicit expiry, distinct from package ignore.
- Optional "fixed in repo" check using `pacman -Si`, if it can be done without
  mirror noise.

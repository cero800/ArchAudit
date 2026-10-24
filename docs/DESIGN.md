# Design

## Problem

An Arch system can be fully up to date and still carry known vulnerabilities:
the fix may not be packaged yet, may still be in `[testing]`, or may concern a
package the user does not think about. Conversely, a pending update is not
automatically a security event. Update indicators optimize for *repository
freshness*; this plugin optimizes for *known exposure*.

The design goal is not to replace `arch-audit`. It is to make its answer
ambient, triable, and explainable without asking the user to remember to run a
command.

## Audience

The primary user is an Arch user who:

- already updates regularly and does not need another update button;
- wants to notice security advisories without subscribing to a feed;
- is comfortable with pacman and the command line, but does not want to
  investigate every advisory from scratch;
- values a shell that stays quiet by default.

Secondary: someone auditing a machine they maintain for others, who needs a
quick answer to "what is currently exposed here?"

## Jobs to be done

1. *While I work:* tell me, without opening anything, whether any installed
   package has a known advisory, and how serious the worst one is.
2. *When something appears:* tell me which package and how bad it is, and let me
   open the authoritative page.
3. *When I triage:* hide the packages I have consciously accepted, and keep the
   rest visible.
4. *When I check later:* tell me what is genuinely new since last time, not the
   whole list again.
5. *When I am ready to act:* give me the correct next command, without running
   it for me.

## Product principles

1. **Ambient before interactive.** The bar answers "is there anything?" in one
   glance. Opening the panel is for triage, not for discovery.
2. **Severity is the primary axis.** Count alone flattens a critical RCE and an
   unknown old advisory into the same number. Colour, sort order, and the filter
   all follow severity.
3. **Read-only is a feature.** No root, no upgrades, no "fix all" button. The
   user stays in control of the machine.
4. **Truth over reassurance.** If a check failed, say so even while showing the
   last good result. Never turn an error into "0 advisories".
5. **Explain the next step.** "No fixed version yet" is more useful than a
   disabled button; "copy `sudo pacman -Syu`" is more correct than a per-package
   install.
6. **Quiet by default.** No notification on first run, no notification below the
   configured severity, no popup for a successful background check.

## Surfaces

### Bar widget

One widget, three signals: glyph, colour, count.

| State | Glyph | Colour | Count | Visible |
| --- | --- | --- | --- | --- |
| Never checked | configured glyph | `on_surface_variant` | — | yes |
| Checking | configured glyph | `secondary` | previous count | yes |
| Advisories | configured glyph | worst severity | total | yes |
| Clean | `shield-check` | `on_surface` | — | unless `hide_on_clean` |
| Failed | `shield-x` | `error` | `!` if no count | always |
| `arch-audit` missing | `shield-x` | `error` | `!` if no count | always |

The configured glyph is intentionally used only while there are advisories.
Clean and failure states have dedicated glyphs so a user who chose a dramatic
icon is not told "everything is fine" by that same icon.

Tooltip rows: status sentence, severity breakdown, new-since-last-check (only
when non-zero), last check age, and the click hint. The tooltip is the only
place that spells out interaction; the bar itself stays compact.

Click mapping:

- Left: toggle panel.
- Right: check now.
- Middle: left to the host's built-in widget-settings gesture.

No hover-only controls, no scroll gestures: the widget is a status object, not
a menu.

### Panel

Attached, 460×580, anchored near the widget. Structure:

```
┌────────────────────────────────────────────┐
│  shield  Security audit          ↻  ⚙  ✕  │
│          3 advisories · 1 critical, 2 high│
├────────────────────────────────────────────┤
│  [banner: missing dependency / last error] │
├────────────────────────────────────────────┤
│  [All severities (3) ▾]   [↓ With fix]     │
├────────────────────────────────────────────┤
│  ● pam 1.6.1-2                    High     │
│    Vulnerable · arbitrary filesystem access│
│    No fixed version yet                    │
│    CVEs: CVE-2025-6020                     │
│    AVG-2901        Open advisory  Copy ... │
│  ────────────────────────────────────────  │
│  ...                                       │
├────────────────────────────────────────────┤
│  Checked 5 minutes ago · 2 ignored         │
└────────────────────────────────────────────┘
```

Header: one-line state, severity mix, and the three global actions (refresh,
settings, close). Refresh is disabled while a check is in flight.

Filter row: a select for severity (with counts) and a toggle for fixed
versions. A select rather than six chips because the panel is narrow and the
counts are secondary information; a chip row would either wrap or truncate. The
fix toggle is separate because "has a fix" is orthogonal to severity.

Advisory card: package name with installed versions is the heading, because
that is what the user recognizes. Severity is a coloured dot plus a text label
(colour is never the only carrier). Status and advisory type follow in muted
text. Fixed version is shown in `primary` when present, `tertiary` for "No
fixed version yet" otherwise. CVE IDs are capped at four plus a `+N` counter to
keep cards scannable while remaining honest about the total. The footer holds
the tracker ID and the two actions.

Empty, missing, error, and waiting states each get an icon, a short title, one
sentence of explanation, and at most one primary action. They are never blank.

Filter state is local and resets on shell restart. It does not affect the badge
or notifications; hiding a severity in the panel must not silently disarm the
ambient signal.

### Notifications

- Fire only for advisories absent from the previous successful check.
- Fire only when the advisory severity is at or above the configured minimum
  (default High).
- Never fire on the first successful check, regardless of threshold.
- Bundle the whole batch into one notification, listing up to three package
  names and a `+N` remainder.
- Do not fire for check failures. The panel and widget carry that state; a
  transient network failure should not steal focus.

The distinction between "new advisory" and "newly visible because I changed the
ignore list" is handled by diffing against the pre-ignore set.

### Settings

Plugin settings are the minimum needed to control noise and scope:

- **Check interval** — 1–168 h, default 6. Startup reuses the cache unless it is
  older than this.
- **Notify about new advisories** — on by default; the escape hatch for users who
  want the badge only.
- **Minimum notification severity** — default High. Medium and Low are available
  for users who want broader coverage; Unknown is not offered because it is not
  an actionable severity.
- **Ignored packages** — a string list, not per-row dismissal. It is explicit,
  copyable between machines, and does not hide an advisory that still affects
  another package.

Widget settings are presentation only: glyph, count visibility, hide when clean.

## Copy and tone

- Short, declarative, no exclamation marks.
- "No known advisories" rather than "You're safe": the tracker has blind spots.
- "No fixed version yet" rather than "Unpatched" (which implies the user is at
  fault).
- "Copy upgrade" with a tooltip naming the exact command; the button never
  claims to perform the upgrade.
- Errors state what failed (missing, timed out, invalid JSON) and keep the cached
  rows visible.
- Ignore is described as display filtering, not as risk acceptance.

## Internationalization and accessibility

- Every user-visible string and every setting label lives in
  `translations/en.json`; no literals in the Luau scripts.
- Plural forms use `trp` with `.one`/`.other` keys.
- Severity is always encoded as colour **and** text, so it survives colour
  blindness and monochrome themes.
- Colour roles come from the active theme (`error`, `tertiary`, `primary`,
  `secondary`, `on_surface_variant`), not hard-coded hex values.
- Minimum text sizes in the panel are 10 px for metadata, 11–12 px for body, and
  15–16 px for headings; the card layout keeps tap targets on the two actions.
- The panel is keyboard-reachable through Noctalia's normal focus handling; no
  custom key handling is implemented.

## Tradeoffs and rejected alternatives

| Alternative | Why not |
| --- | --- |
| Parse `all.json` directly and match installed packages in Luau | Reimplements version comparison and tracker semantics, doubles the failure surface, and re-downloads data `arch-audit` already filters. |
| Show advisories affected by *any* Arch package | Noise with no action; the question is about this machine. |
| Per-package "upgrade" button | Arch does not support partial upgrades; the correct action is a full `-Syu`. Running it from a widget is out of scope. |
| Auto-run `pacman -Syu` | Privilege, consent, and failure recovery all become the plugin's problem. Existing updater plugins do this better. |
| Hide ignored advisories entirely | Ignoring one package must not hide an advisory affecting another. Filtering is per package. |
| Notify on every check | Repeated alerts train users to ignore them. Diffing is the point. |
| Persist filter state | A forgotten filter could hide a critical advisory on the next open; a fresh view is safer. |
| Big severity chips for filtering | Six chips do not fit 460 px without wrapping; a select keeps counts visible and the row stable. |

## Success criteria

- A user can tell within one second whether the machine has a known advisory,
  without opening the panel.
- The panel explains package, severity, installed version, fixed version, and
  the authoritative link for every row.
- No notification on install, no duplicate notification for an unchanged
  advisory, no notification below the configured threshold.
- A failed check never silently becomes "0 advisories".
- The plugin never requires root and never mutates package state.
- A cold start with no network still shows the last cached result.

## Roadmap

- Per-advisory snooze with expiry, separate from package ignore.
- Launcher provider to jump from a package name to its advisory.
- Optional `pacman -Si` check for whether the fixed version is in the
  configured repositories (only if mirror noise can be handled honestly).
- Snapshot history for a small "new since last week" view.
- Additional translations once the English copy is stable.

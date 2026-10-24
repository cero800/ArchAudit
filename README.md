# Arch Audit

A [Noctalia](https://noctalia.dev) plugin that keeps the Arch Security Team
advisories in view: a severity-coloured bar badge, a triage panel, and
notifications for newly published advisories. Read-only, no root, no package
operations.

The plugin itself lives in [`arch-audit/`](arch-audit/).

## Why this exists

Arch users have excellent update notifiers, but updates and security advisories
answer different questions. An update can be pending for a package that has no
known advisory, and an advisory can exist before your mirror has the fixed
build. Arch Audit is deliberately not an updater:

- It reports only advisories that affect **installed** packages.
- It shows the installed version and the fixed version side by side.
- It links to the Arch Security Team page for each advisory.
- It copies `sudo pacman -Syu` instead of running a partial upgrade.
- It never installs, removes, or elevates anything.

## Layout

```
arch-audit/                # the plugin subtree submitted to community-plugins
  plugin.toml              # manifest, settings, entries
  service.luau             # checks, enrichment, cache, scheduling, notifications
  widget.luau              # bar badge
  panel.luau               # triage UI
  lib/audit.luau           # pure normalization/filtering helpers
  translations/en.json     # all UI and settings strings
  README.md                # plugin page on noctalia.dev
  thumbnail.webp           # plugin store card
catalog.toml               # source-repo catalog (not part of the community PR)
docs/ARCHITECTURE.md       # components, data flow, failure modes, decisions
docs/DESIGN.md             # product and UX decisions
tests/audit_test.luau      # pure-helper tests, no Noctalia required
```

## Requirements

- Noctalia `v5.3.0` or newer (`plugin_api = 42`).
- Arch Linux with `arch-audit`, `pacman`, and `xdg-open`.
- `luau` only for running the tests.

```sh
sudo pacman -S arch-audit
```

## Local development

Add this checkout as a path source and enable the plugin once:

```sh
noctalia msg plugins source add dev path "$PWD"
noctalia msg plugins enable cero800/arch-audit
```

`.luau` edits hot-reload. Manifest changes are picked up on the next config
reload. Useful commands:

```sh
noctalia msg plugins list
noctalia msg plugin cero800/arch-audit:service all check
noctalia msg panel-toggle cero800/arch-audit:panel
```

The service keeps its cache and seen-advisory set in the plugin data directory.
To reproduce a first run:

```sh
rm -f "$XDG_DATA_HOME/noctalia/plugins/cero800/arch-audit/snapshot.json"
noctalia msg plugin cero800/arch-audit:service all check
```

Check the shell log if the widget stays at `!` or the panel reports a failure;
the service logs every failed check with an `arch-audit:` prefix.

## Tests

The data layer is pure, so it is tested without starting Noctalia:

```sh
luau tests/audit_test.luau
```

The test suite covers normalization, severity ranking, sorting, pacman output
parsing, ignore semantics, seen/new diffing, filtering, URL validation, and age
formatting.

Syntax-check every entry script with the Luau compiler:

```sh
for file in arch-audit/*.luau arch-audit/lib/*.luau; do
  luau-compile --binary "$file" > /dev/null || exit 1
done
```

## Publishing

The plugin is laid out exactly as the
[community-plugins](https://github.com/noctalia-dev/community-plugins)
repository expects: one top-level directory, `plugin.toml`, scripts, a README
following its template, `thumbnail.webp`, and `translations/en.json` only.

To publish a new version, bump `version` in both `arch-audit/plugin.toml` and
`catalog.toml`, update `updated_at`, tag the commit, and add a
`[[plugin.release]]` row when raising `plugin_api`. The community PR contains
only the `arch-audit/` subtree; `catalog.toml`, `docs/`, and `tests/` stay in
this repository.

## License

MIT. See [`LICENSE`](LICENSE).

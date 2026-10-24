--!nonstrict
-- Unit tests for the pure helpers. Run from the repository root:
--
--   luau tests/audit_test.luau
--
-- No Noctalia process is involved: audit.luau deliberately has no host API
-- calls, so it can be checked in CI or on a machine without the shell.

local audit = require("../arch-audit/lib/audit")

local assertions = 0

local function check(condition, message)
    assertions = assertions + 1
    if not condition then
        error("assertion failed: " .. message, 2)
    end
end

local raw = {
    {
        name = "AVG-2",
        packages = { "pam" },
        status = "Vulnerable",
        severity = "High",
        type = "arbitrary filesystem access",
        fixed = nil,
        issues = { "CVE-2025-6020" },
    },
    {
        name = "AVG-1",
        packages = { "libxml2", "lib32-libxml2" },
        status = "Vulnerable",
        severity = "critical",
        type = "denial of service",
        fixed = "2.14.6-1",
        issues = { "CVE-2025-49794", "CVE-2025-49795" },
    },
    {
        name = "AVG-3",
        packages = { "vim" },
        status = "Unknown",
        severity = "something-new",
        type = "unknown",
        fixed = "",
        issues = nil,
    },
    { name = "AVG-4" },                             -- no packages: dropped
    { name = "AVG-2", packages = { "pam" } },       -- duplicate id: dropped
    "not a table",                                  -- malformed: dropped
}

local installed = {
    pam = "1.6.1-2",
    libxml2 = "2.14.5-1",
    vim = "9.1.0-1",
}

local normalized = audit.normalize(raw, installed)

check(normalized.total == 3, "keeps three valid, unique advisories")
check(normalized.items[1].id == "AVG-1", "sorts critical before high")
check(normalized.items[2].id == "AVG-2", "sorts high before unknown")
check(normalized.items[3].id == "AVG-3", "sorts unknown last")
check(normalized.counts.critical == 1, "counts critical")
check(normalized.counts.high == 1, "counts high")
check(normalized.counts.unknown == 1, "normalises unknown severity")
check(normalized.items[1].fixed == "2.14.6-1", "keeps fixed version")
check(normalized.items[3].fixed == nil, "treats an empty fixed version as absent")
check(normalized.items[3].issues[1] == nil, "tolerates a missing issues array")
check(normalized.items[1].installed[1].version == "2.14.5-1", "uses installed version")
check(normalized.items[1].installed[2].version == nil, "keeps a package without a known version")
check(normalized.items[1].url == "https://security.archlinux.org/AVG-1", "builds advisory URL")
check(audit.advisory_url("../../etc/passwd") == nil, "rejects a malformed advisory id")
check(audit.advisory_url("AVG-123") ~= nil, "accepts a tracker id")

local parsed = audit.parse_installed("pam 1.6.1-2\nlibxml2 2.14.5-1\nbroken-line\n")
check(parsed.pam == "1.6.1-2", "parses pacman -Q output")
check(parsed.libxml2 == "2.14.5-1", "parses a second line")
check(parsed["broken-line"] == nil, "ignores malformed pacman -Q output")

local ignored = audit.apply_ignore(normalized.items, audit.ignore_set({ "libxml2", "lib32-libxml2" }))
check(ignored.total == 2, "drops an advisory once all its packages are ignored")
check(ignored.dropped == 1, "reports the number of dropped advisories")
check(ignored.items[1].id == "AVG-2", "keeps advisories with a non-ignored package")

local partially_ignored = audit.apply_ignore(normalized.items, audit.ignore_set({ "libxml2" }))
local libxml_item = partially_ignored.items[1]
check(partially_ignored.total == 3, "keeps an advisory with one remaining package")
check(#libxml_item.packages == 1, "removes the ignored package from the advisory")
check(libxml_item.packages[1] == "lib32-libxml2", "keeps the non-ignored package")

local ids = audit.ids(normalized.items)
check(ids["AVG-1"] == true and ids["AVG-2"] == true, "builds a seen set")
check(audit.new_items(normalized.items, { ["AVG-1"] = true })[1].id == "AVG-2", "finds new advisories")
check(#audit.new_items(normalized.items, ids) == 0, "finds nothing when everything was seen")
check(#audit.new_items(normalized.items, nil) == 0, "first run is handled by the service, not by new_items")

check(#audit.filter(normalized.items, "high", false) == 1, "filters by severity")
check(#audit.filter(normalized.items, "all", true) == 1, "filters by fixed version")
check(#audit.filter(normalized.items, "critical", true) == 1, "combines severity and fix filters")
check(#audit.filter(normalized.items, "low", false) == 0, "returns an empty list when nothing matches")

check(audit.max_severity(normalized.counts) == "critical", "finds the worst severity")
check(audit.max_severity(audit.severity_counts()) == nil, "returns nil for a clean result")
check(audit.rank("CRITICAL") == 5, "ranks severity case-insensitively")
check(audit.rank("bogus") == 1, "ranks an unknown severity last")

local key, count = audit.age(os.time() * 1000 - 120000)
check(key == "time.minutes_ago", "formats minutes ago")
check(count == 2, "keeps the minute count")
key, count = audit.age(nil)
check(key == "time.never" and count == 0, "handles a missing check timestamp")

check(audit.upgrade_command() == "sudo pacman -Syu", "never suggests a partial upgrade")

print("ok — " .. assertions .. " assertions")

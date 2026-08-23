# Oracle capture scripts

These scripts generate the oracle fixtures under `testdata/oracle/`. They
run on a Windows machine — the DC, or a box with RSAT — that has the
`GroupPolicy` and `ActiveDirectory` PowerShell modules and rights to
create and delete GPOs and OUs in the target domain. **Run them in the
test domain, never a production one.**

A human runs these and commits the generated JSON with `[test-authoring]`
in the commit message (the guard requires it for anything under
`testdata/`). The generated files are the specification; D-03 and the
precedence engine are tested against them.

## O-03 — gPLink ordering (`capture-gplink.ps1`)

### Why it exists

`PLAN.md` §4.2: the MS spec and a widely copied PFE script disagree about
gPLink link ordering. Rather than reason about it, the script records
what GPMC actually reports for a matrix of link configurations. The
recorded `reported` array is the oracle.

The script deliberately contains **no ordering logic**: link order is
taken verbatim from `Get-GPInheritance` (in the order the API returns it)
and the raw `gPLink` attribute is taken verbatim from `Get-ADObject`.
Nothing in the JSON is computed, sorted, or derived. If you are tempted
to add a field that re-derives order, do not — that is the bug this
ticket exists to prevent.

### What it does

1. Removes any leftover `OU=oracle-gplink` subtree and GPOs named
   `oracle-gplink-*` from previous runs (safe to re-run).
2. Creates `OU=oracle-gplink` under the domain root, three GPOs
   (`oracle-gplink-a/b/c`), and 36 scenario OUs. It creates and destroys
   objects **only** under `OU=oracle-gplink` and GPOs named
   `oracle-gplink-*`; it never touches anything else.
3. For each scenario OU it writes `testdata/oracle/gplink/<case>.json`
   (next to the repo root, i.e. the parent of `scripts/`) containing:
   - `ouDN`, `gPOptions` — read verbatim via `Get-ADObject`
   - `rawGPLink` — the `gPLink` attribute string, unmodified
   - `reported` — the array `Get-GPInheritance -Target <OU>` returns,
     per link: GPMC's own `DisplayName`, `GPOId`, `Order`, `Enabled`,
     `Enforced`, copied as-is in the order the API returned them.

Scenario coverage (36 cases): one link; two and three links in all string
orders (case 16 is built by moving links with `Set-GPLink` after
creating them); enforced links in each position, and two enforced at
once; disabled links; disabled+enforced (`gPLinkOptions=3`, which
MS-GPOL 2.2.2 says must behave as **disabled**); the same GPO linked
twice or three times with different options; `gPOptions=1` (block
inheritance) with one link, with a mix, and with no links.

The `gPLinkOptions` numbers appear in the script only to *build* each
scenario (which string to put on the OU). Every recorded value comes
from AD or GPMC.

### How to run

```powershell
# on the DC (or RSAT box), from a checkout of this repo, as an account
# that can create/delete GPOs and OUs (a domain admin in the test domain):
powershell -ExecutionPolicy Bypass -File scripts/capture-gplink.ps1
```

It takes a few minutes (36 OUs, one `Get-GPInheritance` call each). It
prints one line per case with the recorded raw string. If a case's raw
string does not match its description, the tooling surprised us — that
is a finding, keep the case and note it for review.

### Human validation (before committing the JSON)

1. Skim the console output: each `raw=` string should show the expected
   GPOs in the described positions.
2. Open 3–5 JSON files at random — include `28_disenf_only` and one
   duplicate case (e.g. `32_dup_3`).
3. For each, open the same OU in the GPMC GUI (Scope tab, Links) and
   compare by eye:
   - link list and its order vs `reported` (same links, same order);
   - Enabled / Enforced per link vs the GUI;
   - `rawGPLink` vs the attribute in AD (e.g. ADSI Edit).

   `28_disenf_only` must show as **disabled**, not enforced. Note that
   `reported` may also contain links inherited from the domain level
   (e.g. Default Domain Policy) — that is GPMC's own output and is
   intended to be recorded.
4. Commit the generated files:

   ```
   git add testdata/oracle/gplink
   git commit -m "O-03: record gPLink ordering oracle from GPMC [test-authoring]"
   ```

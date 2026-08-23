# OpenGPM — Implementation Backlog

Companion to `PLAN.md`. Section references like (§4.3) point there.

**The agent writes every line of code in this project. You supervise.**

That is only safe because of one structural choice: for every ticket where correctness is *non-local* — where a plausible-looking implementation can pass any test you'd naturally think to write — the ticket is gated on an **external oracle** rather than on human authorship. Epic O builds those oracles first.

The agent still never writes its own tests for correctness-critical code. But the tests don't come from you either; they come from GPMC's own output, from an existing reference implementation, or from a mathematical property. Your job is to review diffs and hold the gates, not to type.

---

## How to use this

### Supervision levels

The tags now describe **how hard the gate is**, not who writes the code. The agent writes all of it.

| Tag | Level | What you do |
|---|---|---|
| 🟢 | **S1 — Spot check** | Skim the diff, confirm the `Accept` command passed, merge. Mechanical work with a local test. |
| 🟡 | **S2 — Full review** | Read every line before merge. Correctness is partly non-local; the test is necessary but not sufficient. |
| 🔴 | **S3 — Oracle-gated** | Cannot merge until it matches an **external oracle** (see Epic O). Full line-by-line review *plus* a green oracle run. |
| ⚫ | **S4 — Oracle + adversarial pass** | S3, then a **second, fresh agent session** given only the spec and the implementation, tasked with finding disagreements. You read its findings before merging. |

Roughly 70% of tickets are S1. The S3/S4 work is concentrated in `internal/transport`, `internal/admx`, and `internal/precedence` — and every one of those now has a named oracle.

### Ticket schema

Every ticket specifies: **Files** (exactly what may be touched), **Contract** (the Go signature, already committed), **Depends on**, **Fixtures**, **Accept** (one command), **Oracle** (for S3/S4), and **Gotchas**.

### The rules that make this work

1. **Contracts before implementations.** Epic 0 defines every shared type. Nothing downstream invents a type. This is what lets tickets run in parallel and stops the model from drifting the data model out from under you.
2. **The implementing agent never writes or edits tests, fixtures, or oracles.** This is the load-bearing rule. A model that writes its own tests writes tests that pass against its own misreading. Tests come from Epic O, from a separate adversarial session, or from a frontier model — never from the session doing the implementing. **This is CI-enforced (F-01b), not left to good behaviour.**
3. **One package per ticket.** The `Files` list is a hard boundary. If a ticket seems to need another file changed, that's a missing ticket — stop and add it.
4. **Fixtures and oracles exist before the ticket starts.** No ticket says "and also produce test data."
5. **Accept is one command, exit code 0.** No "looks right."
6. **Three strikes.** If the agent fails a ticket's `Accept` three times, stop. Don't let it thrash — that's the signal the ticket is underspecified or the oracle is missing. Fix the ticket, don't coach the model.
7. **One ticket, one commit.** Makes `git bisect` meaningful when a fidelity regression shows up forty tickets later.
8. **Every parser bug becomes a fixture, then a ticket.** (§9)

### Red flags in a diff — stop and review hard

The agent's failure mode is plausible code, not broken code. These are the tells:

- A test or fixture file appears in the diff. **Reject immediately**, regardless of how good the reasoning sounds.
- An error path that logs and returns a zero value instead of an error.
- A `default:` or `else` branch that silently drops data. Per §4.4, unparseable input must be *surfaced*, never dropped.
- New dependencies in `go.mod`.
- Anything touching `internal/model/`.
- A comment explaining why the spec is wrong. Sometimes it is — but that's a conversation, not a commit.

### Context budget

The real constraint on a local 27B is usable context, not reasoning (see chat). Practical rules:

- Give the agent the ticket, the contract file, the relevant fixture, and **one** reference implementation excerpt. Not the whole spec, not the whole repo.
- For MS-GPREG and ADMX work, paste the specific spec section, not the page.
- If a ticket needs more than ~8k tokens of context to state, it's too big. Split it.
- Prefer Q8 or fp16 over Q4 for the parser epics. Binary format work punishes quantization noise more than typical CRUD code does.

---

## Epic O — Oracles 🔴

**This epic is what makes the rest delegable. Build it first.**

Each oracle converts a "you have to write this yourself" problem into a "the agent can iterate until the numbers match" problem. None of them require you to write product code — they capture ground truth from systems that already exist.

The agent can write most of the *plumbing* here; you supervise the capture methodology, because a wrong oracle is worse than no oracle. Budget ~1.5 weeks total, and treat it as the highest-leverage time in the project.

### O-01 🔴 Precedence oracle — GPMC Modeling capture

**Files:** `scripts/capture-modeling.ps1`, `testdata/oracle/modeling/`
**Accept:** for ≥200 generated topologies, a committed pair of (topology definition JSON, GPMC Modeling XML result)

Build a randomized topology generator: OU depth 1–6, 1–8 links per SOM, random enforced/disabled flags, random block-inheritance, random security filtering, random half-disabled GPOs, **loopback merge and replace**. Apply each to the test domain, run `Get-GPResultantSetOfPolicy -Mode Planning`, commit the answer.

**This single oracle is what converts all of Epic 5 from 🔴-human to ⚫-agent.** GPMC becomes the spec. The agent iterates until it agrees on 200 topologies, and "subtly wrong precedence engine" — the #1 risk in `PLAN.md` §11 — becomes a number you can watch go up.

Include deliberately adversarial cases: enforced-above-blocked, enforced-vs-enforced at different depths, the same GPO linked twice to one SOM, loopback replace with the computer in a different tree.

### O-02 🔴 ADMX oracle — PolicyPlus differential

**Files:** `scripts/policyplus-diff/`, `testdata/oracle/admx/`
**Accept:** for a corpus of (ADMX catalog + Registry.pol) pairs, committed PolicyPlus-rendered output to diff against

[`Fleex255/PolicyPlus`](https://github.com/Fleex255/PolicyPlus) already solves ADMX resolution correctly. Drive it headlessly over the same inputs and capture what it produces. The agent's resolver must agree.

Covers exactly the failure the plan warns about: `<elements>` handling with `list`+`explicitValue`, `enum` item mapping, `boolean` with `trueList`/`falseList`, `decimal` with `storeAsText`. A resolver that handles only the common cases will pass hand-written tests and fail this.

### O-03 🔴 gPLink ordering oracle — empirical

**Files:** `scripts/capture-gplink.ps1`, `testdata/oracle/gplink/`
**Accept:** ≥30 committed cases of (raw `gPLink` attribute string, GPMC-reported Link Order and precedence)

Small but disproportionately important. The spec and a widely-copied PFE script **disagree** about link ordering (§4.2). Rather than reason about it, capture what GPMC actually reports: create links via the GPMC GUI, dump the raw attribute, record the reported order. Truth by observation.

### O-04 🟢 PReg round-trip property

**Files:** `internal/parse/regpol/property_test.go`
**Accept:** `go test ./internal/parse/regpol/ -run TestRoundTripProperty`

Generate random valid `Registry.pol` structures, marshal, parse, assert a fixed point. Free correctness signal for P-01/P-03 that needs no external system — the only oracle here that costs nothing.

### O-05 🟡 Oracle CI wiring

**Files:** `.github/workflows/oracle.yml`, `Makefile`
**Depends on:** O-01…O-04
**Accept:** `make oracle` runs every oracle comparison and prints a per-oracle agreement percentage

Make the numbers visible on every run. `PLAN.md` §10 calls the fidelity score the project's headline credibility metric; this is the thing that produces it.

---

## Epic 0 — Foundations 🔴

**Agent-written, S3, but reviewed harder than anything else in the project.** Small — maybe 400 lines — and it's the contract every other ticket binds to, so mistakes propagate everywhere.

**Oracle:** none needed; instead, once you approve these files they are **frozen and CI-enforced immutable** (F-01b). That's what makes it safe to delegate — a bad type gets caught in one careful review, and can never silently drift afterward.

Have the agent draft each file directly from `PLAN.md` §4, then review against the spec section line by line. Budget 2 days of your attention.

### F-01 🟡 Repo skeleton

**Files:** `go.mod`, `Makefile`, `.golangci.yml`, `.github/workflows/ci.yml`, `AGENTS.md`
**Accept:** `make lint test` exits 0 on an empty tree.

CI runs `go vet`, `golangci-lint`, `go test ./...`, `govulncheck`. `AGENTS.md` content is in Appendix A.

### F-01b 🔴 Immutability enforcement

**Files:** `.github/workflows/guard.yml`, `scripts/guard.sh`
**Accept:** a PR touching a protected path fails CI with a clear message.

**This ticket is what makes full delegation safe.** Rules 2 and the red-flag list are advisory text in `AGENTS.md`; a model under pressure to make a test pass will eventually violate them. This makes them mechanical.

Fail the build if a commit modifies:

- any `*_test.go` file, **unless** the commit message contains `[test-authoring]` (used only by Epic O and adversarial sessions)
- anything under `testdata/` or `testdata/oracle/`
- anything under `internal/model/` after the Epic 0 freeze commit
- `go.mod` / `go.sum`, unless the commit message contains `[deps]`

Cheap to build, and it converts your most important supervision rule from something you have to remember into something you can't forget.

### F-02 🔴 Canonical domain types

**Files:** `internal/model/gpo.go`, `internal/model/setting.go`, `internal/model/som.go`, `internal/model/security.go`

```go
package model

type GUID string
type SID string
type Class uint8 // ClassMachine | ClassUser | ClassBoth

type GPOFlags uint8
const (
    GPOEnabled         GPOFlags = 0
    GPOUserDisabled    GPOFlags = 1
    GPOComputerDisabled GPOFlags = 2
    GPOAllDisabled     GPOFlags = 3
)

type GPO struct {
    ID                   GUID
    DisplayName          string
    DomainDN             string
    FileSysPath          string
    UserVersion          uint16   // high 16 bits of versionNumber
    ComputerVersion      uint16   // low 16 bits
    SysvolUserVersion    uint16   // from GPT.INI
    SysvolComputerVersion uint16
    Flags                GPOFlags
    FunctionalityVersion int
    MachineExtensions    []CSERef
    UserExtensions       []CSERef
    WMIFilter            *WMIFilterRef
    Security             *SecurityDescriptor
    WhenCreated          time.Time
    WhenChanged          time.Time
}

type SettingSource uint8 // SourceRegistry, SourceSecEdit, SourceGPP,
                         // SourceScript, SourceFolderRedirect, SourceAudit,
                         // SourceWireless, SourceSoftware
type SettingState uint8  // StateEnabled, StateDisabled, StateNotConfigured

type Setting struct {
    Class    Class
    Source   SettingSource
    Category []string      // breadcrumb, e.g. ["Administrative Templates","System"]
    Name     string        // ADMX display name, or raw path if unresolved
    State    SettingState
    Elements []Element     // resolved ADMX element values
    Raw      []RawValue    // ALWAYS retained, even when resolved
    Comment  string
    Unresolved bool        // true = no ADMX definition matched
}

type SettingKey struct { Class Class; Source SettingSource; ID string }
func (s Setting) Key() SettingKey
```

**Gotchas:** `Raw` is non-optional by design — §4.4 requires the registry path always be one click away, and it's how you debug resolver bugs. `SettingKey` must be stable across snapshots or diff (§6.5) breaks.

### F-03 🔴 Directory reader interface

**Files:** `internal/directory/reader.go`

```go
type Reader interface {
    GPOs(ctx context.Context, domainDN string) ([]model.GPO, error)
    SOMTree(ctx context.Context, domainDN string) (*model.SOM, error)
    Sites(ctx context.Context) ([]model.SOM, error)
    WMIFilters(ctx context.Context, domainDN string) ([]model.WMIFilter, error)
    GPOChildren(ctx context.Context, gpoDN string) ([]model.ADChildSetting, error)
    ResolveSIDs(ctx context.Context, sids []model.SID) (map[model.SID]string, error)
}
```

**Gotchas:** Per §3.5 this exists so a `Writer` can be added later. `GPOChildren` covers the AD-stored settings from §4.1 (wireless/wired, `packageRegistration`) — easy to forget it exists; putting it in the interface now forces it.

### F-04 🔴 Snapshot and store interfaces

**Files:** `internal/store/store.go`

Snapshot-oriented, content-addressed (§3.3). `PutSnapshot(ctx, tenant, domain, Snapshot) (SnapshotID, error)`, `GetSnapshot`, `ListSnapshots`, `Search(ctx, query, scope) ([]Hit, error)`.

**Gotchas:** Key everything by `(tenant_id, domain_id)` from day one (§3.6). Retrofitting multi-tenancy into a schema is miserable.

---

## Epic 0.5 — Transport 🔴🟡

**New epic, created by the Linux/Docker pivot (§3.2).** On the Windows design this layer was free — `os.ReadFile` on a UNC path. It is now real work, it is on the critical path, and it is where the architecture can fail.

**Do T-00 before anything else in the project.**

### T-00 🔴 SPIKE: SMB over Kerberos from a container

**Status: DONE — verdict GO.** See `docs/SPIKE-T00.md`.

**Files:** `spike/smb/` (throwaway, not merged)
**Accept:** reads a byte out of `\\dc\SYSVOL\` from a Linux container, authenticated by **Kerberos with NTLM disabled**, against a DC with **SMB signing required** and SMB3 encryption enabled.

**Oracle:** none possible — this is empirical. The acceptance criterion *is* the oracle: bytes come back, or they don't. Agent-writable, but **you must verify the DC is genuinely configured with signing required and NTLM disabled**, or the spike passes for the wrong reason and you discover it in month three. Check the DC's configuration yourself before trusting a green result.

Evaluation outcome: [`CloudSoda/go-smb2`](https://github.com/CloudSoda/go-smb2) — **chosen for T-03** (shares `jcmturner/gokrb5/v8` with the LDAP path, provides `Share.DirFS()` `fs.FS`); [`jfjallid/go-smb`](https://github.com/jfjallid/go-smb) (active mid-2026, SMB3) — passed unmodified, kept as the proven fallback (ships its own gokrb5 fork, no `fs.FS`); [`hirochachacha/go-smb2`](https://github.com/hirochachacha/go-smb2) — **rejected**: has no `Krb5Initiator` (CloudSoda's fork added that), `Initiator` methods are unexported, dead since 2022-07.

**Go/no-go gate on the entire Docker architecture — resolved GO.** Pure-Go SMB over Kerberos is proven; the `cifs`-mount fallback in a privileged container (which breaks every container-hardening claim in §5) is not needed.

### T-01 🔴 Keytab and TGT lifecycle

**Files:** `internal/transport/krb/krb.go`
**Contract:** `func FromKeytab(path, principal, realm string) (*Client, error)`, `func (c *Client) GSSAPIClient() gssapi.Client`
**Accept:** `go test -tags=integration ./internal/transport/krb/`

**Oracle:** V-03 transport failure-mode suite — a DC deliberately misconfigured in each dimension (skewed clock, expired TGT, wrong SPN, NTLM disabled). The agent must produce a *specific* error for each, not a generic auth failure.

**Gotchas:** the failure modes here are all operational, not logical, which is why the test environment is the oracle. TGT renewal before expiry. **Clock skew detection with a specific error message** (§5): Kerberos dies past ~5 minutes drift and the native error is useless. **Keytab KVNO:** `jcmturner/gokrb5/v8` matches keytab entries by KVNO exactly — a keytab whose KVNO label is stale relative to the KDC fails with a misleading "AS_REP invalid or client key incorrect" even though the key material is current. T-01 owns the retry (once, relabelling to the KDC-issued KVNO) and the specific error naming the KVNO mismatch; V-03 covers it. Same defect would hit the D-01 LDAP bind — it is a Kerberos-client issue, not SMB.

This ticket largely determines whether first-run succeeds, and per `PLAN.md` §11 that's the top adoption risk. Review the *error messages* as carefully as the logic — an agent will happily return `fmt.Errorf("auth failed: %w", err)` and pass every test while guaranteeing you a support queue.

### T-02 🟡 SRV-based DC discovery

**Files:** `internal/transport/discover.go`
**Contract:** `func DiscoverDCs(ctx context.Context, domain string) ([]DC, error)`
**Accept:** `go test ./internal/transport/ -run TestSRVParse` (fixture-based)

`_ldap._tcp.dc._msdcs.<domain>`, honouring priority and weight. Must expose a **pinned** DC choice — §4.1 requires LDAP and SMB to hit the same one. Allow explicit override in config for locked-down networks.

### T-03 🟡 SMB client wrapper

**Files:** `internal/transport/smbx/smbx.go`
**Contract:** `func (c *Client) Open(uncPath string) (fs.File, error)`, `func (c *Client) ReadDir(uncPath string) ([]fs.DirEntry, error)`
**Depends on:** T-00 (library choice), T-01
**Accept:** `go test -tags=integration ./internal/transport/smbx/`

**Gotchas:** Translate UNC → share + path. `gPCFileSysPath` is `\\<domain>\SysVol\...` where `<domain>` is a **domain name, not a host** — resolve it to the pinned DC (T-02), don't treat it literally. Require signing; never negotiate down. Expose an `fs.FS` so the parsers stay transport-agnostic and testable against `os.DirFS`.

### T-04 🟢 fs.FS test doubles

**Files:** `internal/transport/fstest/`
**Accept:** `go test ./internal/transport/fstest/`

Lets every Epic 2/3 ticket run against a local directory with no DC. Small ticket, unblocks a lot of parallel agent work.

---

## Epic 1 — Directory access

### D-01 🟡 LDAP connection: GSSAPI bind + SD flags control

**Files:** `internal/transport/ldapx/conn.go`
**Contract:** `func Dial(cfg Config) (*Conn, error)`, `func (c *Conn) SearchSD(ctx, base, filter string, attrs []string) ([]*ldap.Entry, error)`
**Depends on:** F-03, T-01, T-02
**Accept:** `go test -tags=integration ./internal/transport/ldapx/ -run TestSDFlagsControl`

GSSAPI/SPNEGO bind from the keytab, with simple-bind-over-LDAPS fallback. Mounted CA bundle for cert verification. **Refuse plaintext LDAP.**

**Gotchas:** 🟡 not 🟢 because of the §4.6 trap — you **must** send `LDAP_SERVER_SD_FLAGS_OID` (`1.2.840.113556.1.4.801`) requesting DACL+Owner+Group only. Omit it and `nTSecurityDescriptor` comes back *missing* rather than erroring, for exactly the low-privilege account the product is designed to run as. Test must assert the attribute is present when bound as a non-admin.

Also pin the connection to a **specific DC** (§4.1) — expose the chosen DC so `sysvol` can bind to the same one.

### D-02 🟢 groupPolicyContainer enumeration

**Files:** `internal/directory/ldap/gpo.go`
**Contract:** implements `Reader.GPOs`
**Depends on:** D-01, F-02
**Fixtures:** `testdata/ldap/gpo_entries.json` (captured LDAP entries)
**Accept:** `go test ./internal/directory/ldap/ -run TestParseGPOEntry`

**Gotchas:** `versionNumber` is packed — user = `v >> 16`, computer = `v & 0xFFFF`. Read `gPCFunctionalityVersion`. Do not filter out GPOs with unreadable SDs; flag them.

### D-03 ⚫ gPLink parsing and ordering

**Files:** `internal/directory/gplink.go`
**Contract:** `func ParseGPLink(s string) ([]model.Link, error)` — returned slice in **precedence order, highest first**
**Depends on:** F-02, **O-03**
**Fixtures:** `testdata/oracle/gplink/` (from O-03)
**Accept:** `go test ./internal/directory/ -run TestParseGPLink` — all 30+ observed cases

**Gotchas:** The single highest-risk small function in the project (§4.2), and the clearest illustration of why oracles beat reasoning here. LAST entry in the string = Link Order 1 = **highest** precedence (reverse the string); confirmed by the O-03 fixtures, which are the authority — if the implementation disagrees with them it is wrong. A widely-copied PFE script says the opposite, so the model's training data probably contains both answers — meaning it may argue confidently for the wrong one.

**Do not let the agent reason about ordering. O-03 recorded what GPMC actually does; the fixtures are the answer.** If the implementation disagrees with the fixtures, the implementation is wrong, full stop.

Also: `gPLinkOptions=3` reports as **disabled**, not enforced. gPLinkOptions decode: Enabled = NOT (opt AND 1), Enforced = (opt AND 2). Disabled links (opt 1 or 3) still receive an Order and still appear — they are not dropped (see fixture 21_dis_first). opt 3 reports Enabled=false AND Enforced=true; it is treated as disabled via the Enabled flag, not by discarding enforcement. The same GPO may appear **twice** on one SOM — do not dedupe by GUID. Links may reference **other domains**.

### D-04 🟢 SOM tree assembly

**Files:** `internal/directory/ldap/som.go`
**Depends on:** D-02, D-03
**Accept:** `go test ./internal/directory/ldap/ -run TestSOMTree`

**Gotchas:** `gPOptions=1` = block inheritance. Site links live in the Configuration NC, not the domain NC.

### D-05 🟢 WMI filter enumeration

**Files:** `internal/directory/ldap/wmi.go`
**Accept:** `go test ./internal/directory/ldap/ -run TestWMIFilters`

`msWMI-Som` under `CN=SOM,CN=WMIPolicy,CN=System`; query text in `msWMI-Parm2`. Parse the query for *display*; do not attempt to execute it.

### D-06 🟡 Security descriptor / ACE parsing

**Files:** `internal/directory/sddl/parse.go`
**Contract:** `func Parse(b []byte) (*model.SecurityDescriptor, error)`, `func (sd *SecurityDescriptor) AppliesTo(sids []model.SID) bool`
**Fixtures:** `testdata/sddl/*.bin` with expected JSON
**Accept:** `go test ./internal/directory/sddl/`

**Gotchas:** Apply Group Policy extended right = `edacfd8f-ffb3-11d1-b41d-00a0c968f939`; requires **both** that right and Read. Binary SD layout is fiddly — fuzz it (§9), it consumes attacker-influenceable input.

### D-07 🟢 AD-stored GPO child settings

**Files:** `internal/directory/ldap/children.go`
**Depends on:** D-02
**Accept:** `go test ./internal/directory/ldap/ -run TestGPOChildren`

`ms-net-ieee-80211-GroupPolicy` / `ms-net-ieee-8023-GroupPolicy`, and `packageRegistration` under `CN=Packages,CN=Class Store,CN=Machine,<GPO DN>`. Best-effort rendering; label clearly if not fully parsed.

---

## Epic 2 — SYSVOL

### S-01 🟢 GPT walker

**Files:** `internal/sysvol/walk.go`
**Contract:** `func Walk(fsys fs.FS, root string) (*Artifacts, error)` — returns discovered file paths by kind
**Depends on:** T-03, T-04
**Accept:** `go test ./internal/sysvol/ -run TestWalk` (against `testdata/gpt/sample/` via `os.DirFS`)

Takes an `fs.FS`, so it neither knows nor cares that it's reading over SMB. Stays 🟢 and fully testable offline.

**Gotchas:** Discover GPP types by **enumerating `Preferences/*/` directories**, not from a hardcoded list of 20 or 21 (§4.5). Find both `fdeploy1.ini` and `fdeploy.ini`.

### S-02 🟢 GPT.INI

**Files:** `internal/sysvol/gptini.go`
**Accept:** `go test ./internal/sysvol/ -run TestGPTIni`

Same packed-DWORD split as D-02. Feeds the version-mismatch check — and remember the DC-pinning caveat (§4.1) belongs in the *collector*, not here.

---

## Epic 3 — Parsers

The bulk of the mechanical work. All 🟢 except where noted.

### P-01 🟡 Registry.pol reader

**Files:** `internal/parse/regpol/read.go`
**Contract:**
```go
type Entry struct { Key, Value string; Type uint32; Data []byte }
func Parse(r io.Reader) ([]Entry, error)
```
**Fixtures:** `testdata/regpol/{basic,unicode,empty,truncated,all_types}.pol` + expected JSON
**Accept:** `go test ./internal/parse/regpol/ -run TestParse`
**Reference:** [`ubuntu/adsys`](https://github.com/ubuntu/adsys) PReg parser

**Gotchas:** Header is 8 bytes: `PReg` (`0x67655250`) + LE DWORD version `1`. Records are literally `[key;value;type;size;data]` with brackets and semicolons as **UTF-16LE characters**. `size` is in bytes. Key/value strings include their terminating null.

Microsoft's own format page is **wrong in places** — follow Margosis's corrections (§4.3). Reject malformed input, never panic.

### P-02 🔴 Registry.pol directive classification

**Files:** `internal/parse/regpol/directive.go`
**Contract:** `func Classify(e Entry) (Directive, string)`
**Depends on:** P-01
**Oracle:** V-01b fidelity corpus — real `.pol` files containing all seven directive forms
**Accept:** `go test ./internal/parse/regpol/ -run TestClassify`

**Paste the gotcha list below into the ticket verbatim.** Every item contradicts Microsoft's published documentation, which means it also likely contradicts the model's training data. Without these stated explicitly, a confident wrong implementation is the expected outcome.

**Gotchas:** every one of these has a documented-vs-reality discrepancy (§4.3):
- `**DeleteKeys` — the *key* field is **ignored/empty**; paths live in `Data` as semicolon-delimited UTF-16LE. Microsoft documents the opposite.
- `**Comment:` — undocumented but real. Miss it and comments render as bogus settings.
- `**SecureKey` — inert on Win7 SP1+. Must not render as an effective setting.
- Match **case-insensitively**; accept `**delvals.` and `**DelVals`.

### P-03 🟢 Registry.pol writer

**Files:** `internal/parse/regpol/write.go`
**Contract:** `func Marshal(w io.Writer, entries []Entry) error`
**Depends on:** P-01
**Accept:** `go test ./internal/parse/regpol/ -run TestRoundTrip`

Not needed for v1 reads. Build it anyway — the round-trip property test (§9) is the cheapest correctness signal available for P-01, and it's the seam for v2 writes (§3.5).

### P-04 🟡 GptTmpl.inf

**Files:** `internal/parse/secedit/parse.go`
**Fixtures:** `testdata/secedit/*.inf`
**Accept:** `go test ./internal/parse/secedit/`

UTF-16 INI. Sections: `[System Access]`, `[Event Audit]`, `[Privilege Rights]`, `[Registry Values]`, `[Service General Setting]`, `[File Security]`, `[Registry Keys]`. 🟡 because `[Privilege Rights]` values are SID lists needing resolution, and `[Registry Values]` has its own type encoding distinct from `Registry.pol`.

### P-05 🟢 GPP — one ticket per type

**Files:** `internal/parse/gpp/<type>.go` + `<type>_test.go`
**Depends on:** P-05a
**Accept:** `go test ./internal/parse/gpp/ -run TestParse<Type>`

**P-05a 🟡 — hand-write `drives.go` first** as the reference all others copy, plus `common.go` for the shared `<Filters>` / `<Properties>` wrapper structure. Everything below is then a 🟢 fill-in-the-struct ticket against that template.

| Ticket | Type | Ticket | Type |
|---|---|---|---|
| P-05b | Printers | P-05k | EnvironmentVariables |
| P-05c | Registry | P-05l | IniFiles |
| P-05d | Shortcuts | P-05m | NetworkOptions |
| P-05e | ScheduledTasks | P-05n | PowerOptions |
| P-05f | Groups | P-05o | DataSources |
| P-05g | Files | P-05p | DeviceSettings |
| P-05h | Folders | P-05q | Regional |
| P-05i | Services | P-05r | StartMenu |
| P-05j | Applications | P-05s | FolderOptions, InternetSettings |

**This is the ideal agent workload** — 18 near-identical tickets with a committed reference. Run them in parallel if your setup allows.

### P-06 🟡 GPP item-level targeting

**Files:** `internal/parse/gpp/filters.go`
**Contract:** `func ParseFilters(d *xml.Decoder) (*model.FilterTree, error)`
**Depends on:** P-05a
**Accept:** `go test ./internal/parse/gpp/ -run TestFilterTree`

**Gotchas:** 🟡 — this is a **nested boolean tree**, not a flat list. `bool="AND"|"OR"` and `not="1"` on each node, with grouping via `<FilterCollection>`. Getting the tree shape wrong yields output that looks fine and means something else. Test with deliberately deep nesting.

### P-07 🟢 Scripts

**Files:** `internal/parse/scripts/parse.go` — `scripts.ini`, `psscripts.ini`
**Accept:** `go test ./internal/parse/scripts/`

### P-08 🟢 Folder redirection

**Files:** `internal/parse/fdeploy/parse.go`
**Accept:** `go test ./internal/parse/fdeploy/`

Handle **both** `fdeploy1.ini` (MS-GPFR Version One, tried first by clients) and `fdeploy.ini` (Version Zero fallback).

### P-09 🟢 Advanced audit policy

**Files:** `internal/parse/audit/parse.go` — `audit.csv`
**Accept:** `go test ./internal/parse/audit/`

### P-10 🟢 Comments

**Files:** `internal/parse/comment/parse.go` — `comment.cmtx`
**Accept:** `go test ./internal/parse/comment/`

### P-11 🟢 Fuzz harnesses

**Files:** `internal/parse/*/fuzz_test.go`
**Depends on:** P-01…P-10
**Accept:** `go test -fuzz=Fuzz -fuzztime=60s ./internal/parse/...`

Mechanical and valuable — these parsers consume attacker-influenceable SYSVOL content (§9).

---

## Epic 4 — ADMX ⚫

**The hardest package — and fully delegable now, because O-02 turns PolicyPlus into the specification.**

The agent implements; `make oracle-admx` says whether it's right. Target ≥99.5% agreement with PolicyPlus across the corpus, with every disagreement triaged rather than tolerated.

Point the agent at [`Fleex255/PolicyPlus`](https://github.com/Fleex255/PolicyPlus) as a reference, but give it excerpts, not the repo — pasting whole files is the fastest way to burn the context this work actually needs.

### A-01 🟢 ADMX/ADML XML unmarshalling

**Files:** `internal/admx/schema.go`
**Accept:** `go test ./internal/admx/ -run TestUnmarshal`

Pure `encoding/xml` struct definitions. Genuinely 🟢 — no semantics, just shape.

### A-02 🟡 Catalog loading and ADML string resolution

**Files:** `internal/admx/catalog.go`
**Contract:** `func LoadCatalog(fsys fs.FS, lang string) (*Catalog, error)`
**Accept:** `go test ./internal/admx/ -run TestLoadCatalog`

Language fallback must never fail the load — degrade to raw paths.

### A-02b 🟢 Catalog sourcing and fetch

**Files:** `internal/admx/source.go`, `internal/admx/fetch.go`
**Depends on:** A-02, T-03
**Accept:** `go test ./internal/admx/ -run TestSourcePriority`

**New, and load-bearing because of the pivot (§4.4).** There is no local `C:\Windows\PolicyDefinitions` off-Windows. Priority: Central Store over SMB → mounted `/etc/opengpm/policydefinitions` → fetched Microsoft ADMX package into `/data/admx/<release>/`, pinned by version and checksum.

Microsoft's ADMX files **must not be vendored into the repo** (§10) — the container ships with no catalog. The "no catalog configured" state must surface as a loud UI banner, never silent raw-path rendering.

### A-03 🔴 Category tree and supportedOn

**Files:** `internal/admx/category.go`
**Oracle:** O-02 category breadcrumbs
**Accept:** `go test ./internal/admx/ -run TestCategoryTree`

`<parentCategory>` chains cross ADMX file boundaries and can be cyclic in malformed sets. Must produce the same breadcrumb GPMC shows — which O-02 has captured, so this is checkable rather than eyeballed.

### A-04 ⚫ Policy resolver

**Files:** `internal/admx/resolve.go`
**Contract:**
```go
func (c *Catalog) Resolve(entries []regpol.Entry, class model.Class) (resolved []model.Setting, unresolved []regpol.Entry)
```
**Depends on:** A-01…A-03, P-01, P-02, **O-02**
**Oracle:** O-02 — must reach ≥99.5% agreement with PolicyPlus
**Accept:** `go test ./internal/admx/ -run TestResolve` **and** `make oracle-admx` ≥ 99.5%

**Gotchas:** `<elements>` handling is where this goes silently wrong. `list` with `explicitValue` uses prefix-numbered keys; `enum` maps values through `<item>`/`<value>`; `boolean` has independent `trueValue`/`falseValue` *and* `trueList`/`falseList`; `decimal` has `storeAsText`.

A resolver handling only the common cases passes any hand-written test and mangles perhaps 5% of real settings. **That 5% is exactly what O-02 exists to surface** — it is the difference between a tool people trust and one they check against GPMC every time.

Must return `unresolved` — never drop. Those become GPMC's "Extra Registry Settings" (§4.4). Watch specifically for an implementation that quietly drops entries it can't match to raise its own agreement score; the oracle should count unresolved entries too.

### A-05 🟢 Unresolved-setting renderer

**Files:** `internal/admx/extra.go`
**Depends on:** A-04
**Accept:** `go test ./internal/admx/ -run TestExtraRegistry`

---

## Epic 5 — Precedence ⚫

**Agent-written, gated on O-01 throughout.** ~600 lines that determine whether the product tells the truth.

This epic used to say "write this yourself." O-01 changes that: GPMC's own Modeling output over 200 randomized topologies becomes the specification, and the agent iterates until agreement hits 100%. You supervise a percentage instead of authoring an engine.

**Standing rule for every ticket in this epic:** `make oracle-precedence` must report **100%** agreement, not 99%. A single disagreeing topology means a real rule is wrong — chase it rather than rationalizing it. This is the one place in the project where near-enough is not good enough, because a wrong answer here is indistinguishable from a right one to the user.

**All tickets here are S4** — after the oracle is green, run a fresh adversarial session over the implementation before merging.

### PR-01 ⚫ SOM chain resolution

**Files:** `internal/precedence/chain.go`
**Oracle:** O-01, chain-only subset
**Accept:** `go test ./internal/precedence/ -run TestChain`

Local → Site → Domain → OU → nested OUs (§4.7).

### PR-02 ⚫ Inheritance, blocking, enforcement

**Files:** `internal/precedence/inherit.go`
**Depends on:** PR-01, D-03, O-01
**Oracle:** O-01 topologies tagged `enforced` and `blocked`
**Accept:** `go test ./internal/precedence/ -run TestInherit` **and** `make oracle-precedence` = 100%

Block inheritance drops everything above **except enforced**. Among enforced links, **higher in the tree wins** — the inversion of the normal rule.

This is the rule most likely to be implemented backwards, and the one the oracle catches most reliably. Don't accept an implementation that passes the unit tests but fails two topologies.

### PR-03 ⚫ Filtering

**Files:** `internal/precedence/filter.go`
**Depends on:** D-06, O-01
**Oracle:** O-01 topologies tagged `filtered`
**Accept:** `go test ./internal/precedence/ -run TestFilter` **and** oracle green

Security filtering, `flags` half-disabling, WMI filter match/unevaluated. **MS16-072**: user-side GPOs are fetched in the *computer's* context — evaluate the computer account's token for user GPOs too (§4.6).

> The MS16-072 behaviour is subtle enough that GPMC Modeling may not reproduce it identically. Where oracle and spec disagree here, **flag it for review rather than silently matching the oracle** — this is the one known place the oracle may be the weaker authority.

### PR-04 ⚫ Loopback

**Files:** `internal/precedence/loopback.go`
**Depends on:** PR-02, PR-03, O-01
**Oracle:** O-01 topologies tagged `loopback-merge` and `loopback-replace`
**Accept:** `go test ./internal/precedence/ -run TestLoopback` **and** oracle green

Replace: discard user's OU-derived user settings entirely, substitute the computer SOM chain's. Merge: user list first, then computer's, computer wins. Omitting this makes modeling confidently wrong in RDS/VDI/kiosk environments (§4.7).

Loopback interacts with enforcement and blocking in ways that are genuinely hard to reason about. Let the oracle arbitrate — that's precisely why it exists.

### PR-05 ⚫ Merge with winner/loser retention

**Files:** `internal/precedence/merge.go`
**Oracle:** O-01 full result comparison including per-setting precedence values
**Accept:** `go test ./internal/precedence/ -run TestMerge` **and** oracle green

Must retain **every** contributing GPO per setting with the winner marked (RSoP `precedence = 1` semantics). Showing *why* a setting lost is the product's best feature — don't collapse it.

Compare the **full ordered contribution list** against GPMC, not just the winner. An engine that picks the right winner via the wrong path will pass a winner-only check and produce nonsense in the §6.4 explanation panel.

### PR-06 🟡 Modeling API surface

**Files:** `internal/precedence/model.go`
**Depends on:** PR-01…PR-05
**Accept:** `go test ./internal/precedence/ -run TestModeling`

Thin orchestration over the above. Safe to delegate once the engine is yours.

---

## Epic 6 — Store, snapshots, search

### ST-01 🟢 SQLite schema and migrations
### ST-02 🟢 Snapshot write/read
### ST-03 🟡 Content-addressed incremental collection

Skip re-parse when `versionNumber` / GPT.INI version / mtime are unchanged (§3.3). 🟡 because a wrong cache key means stale data presented as fresh — the worst failure mode in a reporting tool. Include a forced-full-sweep escape hatch.

### ST-04 🟢 FTS5 index and search
### ST-05 🟢 Snapshot diff engine

**Depends on:** F-02 (`SettingKey` stability)
**Accept:** `go test ./internal/store/ -run TestDiff`

---

## Epic 7 — Collector and API

### C-01 🟡 Collector orchestration

**Depends on:** T-02
**Gotchas:** Pin LDAP and SMB to the **same DC** (§4.1) or the flagship version-mismatch check emits false positives under replication lag. Now enforced through T-02's pinned-DC handle rather than by accident of the OS redirector.

### C-02 🟢 Scheduling
### C-03 🟢 REST handlers + OpenAPI generation
### C-04 🟡 Auth — **OIDC primary**, SPNEGO optional

Changed by the pivot (§5): Negotiate SSO from a non-domain-joined container is awkward, so OIDC becomes the default admin login path.

### C-05 🟢 RBAC middleware
### C-06 🟢 Audit log
### C-07 🟢 Exporters — HTML, CSV, JSON

### C-08 🟡 `opengpm doctor`

**Files:** `cmd/opengpm/doctor.go`
**Depends on:** T-01, T-02, T-03, D-01
**Accept:** `go test -tags=integration ./cmd/opengpm/ -run TestDoctor`

Replaces the Windows-only `Test-OpenGPMPermissions.ps1`. Checks DNS/SRV resolution, clock skew, keytab validity, LDAP bind, SMB access with signing, ADMX catalog presence, and effective permissions — each with a specific remediation message. Per §11 this is the main defence against Kerberos first-run friction, so it deserves more care than a typical 🟢 ticket.

---

## Epic 8 — Frontend (all 🟢)

Generated TypeScript client from the OpenAPI spec means the model never invents API types.

| Ticket | Component |
|---|---|
| UI-01 | App shell, routing, generated API client |
| UI-02 | Forest/domain/OU tree |
| UI-03 | GPO inventory table (TanStack Table) |
| UI-04 | Scope / Details / Delegation tabs |
| UI-05 | Settings tree, virtualized (TanStack Virtual) |
| UI-06 | Filter-tree viewer for GPP item-level targeting |
| UI-07 | Modeling wizard incl. **loopback toggle** |
| UI-08 | Winner/loser precedence panel |
| UI-09 | Diff views (side-by-side + unified) |
| UI-10 | Health report dashboard |
| UI-11 | Global search |
| UI-12 | Export dialogs |
| UI-13 | Dark mode, keyboard nav, WCAG 2.1 AA pass |

UI-05 needs an explicit perf budget in its ticket — thousands of nodes, must not jank.

---

## Epic 9 — Health checks (all 🟢 after H-01)

### H-01 🟡 Check registry/plugin framework

One check = one file implementing `Check` (§10, keeps contribution friction low). Everything after is 🟢.

Then one ticket per check from §6.6. Highest value first: **MS16-072 filtering breakage**, AD/SYSVOL version mismatch, GPC/GPT ACL divergence, empty GPOs, unlinked GPOs, non-default owners, orphaned SYSVOL folders, duplicate display names, broken WMI filter refs, `gPCFunctionalityVersion ≠ 2`, dead file-server references in GPP, settings configured but never effective.

---

## Epic 10 — Fidelity harness 🔴

Restructured into two stages by the pivot (§9). Windows is now a **fixture-generation** dependency, not a test-run dependency — the everyday suite runs on Linux with no Windows licence, which is strictly better for contributors.

### V-01a 🔴 Corpus capture (Windows, occasional)

**Files:** `scripts/capture-corpus.ps1`
**Accept:** produces, for each GPO in the test domain, a `Get-GPOReport -ReportType Xml` output **and** a byte-for-byte copy of its SYSVOL GPT, normalized and committed under `testdata/corpus/`.

Run when the corpus grows, not per build. Add "refresh fidelity corpus" to the release checklist or it silently rots.

### V-01b 🔴 Offline comparison (Linux, every CI run)

**Files:** `internal/verify/fidelity.go`
**Depends on:** V-01a, F-02
**Accept:** `go test ./internal/verify/` — **no build tag, no domain, no Windows.**

Parse the committed SYSVOL bytes with our own code, normalize both sides, assert equivalence, report a percentage.

**Build this before Epic 3, not after.** It defines "done" for every parser ticket and is the project's headline credibility metric (§9, §10).

Target: ≥99% setting-level agreement on a 200-GPO corpus, every discrepancy triaged.

### V-02 🟡 Dual-target integration matrix

**Files:** `.github/workflows/integration.yml`, `test/domains/`
**Accept:** the integration suite runs green against **both** a Windows AD DC and a Samba AD DC.

Samba is a CI-tested target, not best-effort (§3.7). Divergences get explicit skips with a documented reason — never silent branching.

### V-03 🟡 Transport failure-mode tests

**Files:** `test/transport/`
**Depends on:** T-01, T-03
**Accept:** `go test -tags=integration ./test/transport/`

SMB signing required, SMB3 encryption, NTLM disabled, expired TGT renewal, deliberate clock skew. These are the new failure modes the Windows design didn't have, and they fail in production rather than in unit tests.

---

## Epic 11 — Packaging (all 🟢)

Replaces the MSI/Windows-service work entirely.

| Ticket | Item |
|---|---|
| PK-01 | Multi-stage Dockerfile — `CGO_ENABLED=0`, distroless/scratch, non-root UID, read-only rootfs |
| PK-02 | Multi-arch build (amd64 + arm64), cosign signing, SBOM |
| PK-03 | `docker-compose.yml` example with keytab + CA secret mounts |
| PK-04 | Helm chart |
| PK-05 | Config via env vars + file, twelve-factor style |
| PK-06 | Docs site: first-run guide, **keytab creation walkthrough** (`ktpass` / `samba-tool`), DNS requirements, permissions matrix |
| PK-07 | Health/readiness endpoints |

PK-06 matters more than it looks. Per §11, Kerberos first-run friction is the top adoption risk, and the doc is most of the mitigation.

---

## Suggested execution order

```
T-00  SMB/Kerberos spike        ← GO/NO-GO on the whole architecture
    ↓
F-01, F-01b  (guard rails BEFORE the agent can do damage)
    ↓
F-02…F-04  (contracts; review hard, then freeze)
    ↓
Epic O  — O-01…O-05  ← THE UNLOCK. Nothing hard is delegable before this.
    ↓
T-01…T-04
    ↓
V-01a/V-01b fidelity harness   ← before any parser
    ↓
D-01…D-07  ∥  S-01, S-02  ∥  P-01…P-03
    ↓
P-04…P-11  (big parallel run — 25+ tickets, mostly unattended)
    ↓
A-01…A-05  (oracle-gated on O-02)
    ↓
PR-01…PR-06  (oracle-gated on O-01)
    ↓
ST, C, UI, H
    ↓
V-02, V-03, Epic 11
```

**Build order note:** F-01b (immutability enforcement) comes second, immediately after the repo exists. It's a ~50-line CI script, and until it's in place your most important supervision rule is just a sentence in a file the model is free to ignore.

### Your supervision budget

| Phase | Your time | What you're actually doing |
|---|---|---|
| T-00 spike | ~3 days | Verifying the DC config is genuinely hostile, reading the result |
| F-01…F-04 | ~2 days | One careful review of ~400 lines of types, then freeze |
| **Epic O** | **~1.5 weeks** | **Designing capture methodology, validating oracle correctness** |
| Parsers (P, D, S) | ~4 days | Diff review across ~35 tickets, mostly skimming |
| ADMX (Epic 4) | ~3 days | Triaging O-02 disagreements |
| Precedence (Epic 5) | ~4 days | Triaging O-01 disagreements, adversarial passes |
| Everything else | ~1 week | Routine diff review |
| **Total** | **~4.5 weeks** | Down from 8–9 weeks of authorship |

The trade is explicit: **Epic O adds ~1.5 weeks of upfront work and removes ~6 weeks of hand-written code.** It also produces something you didn't have before — a published agreement percentage against GPMC, which `PLAN.md` §10 identifies as the project's credibility metric.

### What you're still on the hook for

Delegating authorship doesn't delegate judgement. Three things stay yours:

1. **Oracle correctness.** A wrong oracle is worse than no oracle — it launders a bug into a verified fact. Validate O-01's captures by hand on a few topologies before trusting the other 197.
2. **The MS16-072 caveat in PR-03**, where the oracle may be the weaker authority and the spec should win.
3. **Deciding when a disagreement is a bug versus a known-acceptable divergence.** The agent will want to close the gap; sometimes the right answer is a documented skip.

---

## Appendix A — `AGENTS.md`

Commit this at the repo root; OpenCode reads it automatically.

```markdown
# Agent rules for OpenGPM

You write all the code in this project. A human reviews every diff, and
CI mechanically enforces the rules below. Violating them wastes a review
cycle — it will not get past the guard job.

## Hard rules
1. Only modify files listed in the ticket's `Files` section. Never touch
   another package. If the ticket appears to require it, STOP and say so.
2. Never modify or create `*_test.go` files, anything under `testdata/`,
   or anything under `internal/model/`. Tests and fixtures are the
   SPECIFICATION, not part of the work. CI rejects these changes.
   If a test seems wrong, STOP and say so — do not "fix" it.
3. Never add a dependency. Stdlib plus what is already in `go.mod`.
4. Never delete, skip, or `t.Skip()` a failing test.
5. If the ticket names an Oracle, the oracle's recorded behaviour
   OUTRANKS any specification, documentation, or knowledge you have.
   Oracles are captured from real systems. When you disagree with one,
   you are wrong. Say so and stop rather than adjusting the oracle.

## When you get stuck
After two failed attempts at the Accept command, STOP and report:
what you tried, what failed, and what you think the ticket is missing.
Do not try a third approach. A stuck ticket is usually an
underspecified ticket, and that is a human problem to fix.

## Definition of done
- The ticket's `Accept` command exits 0.
- The ticket's `Oracle` check passes at the stated threshold, if any.
- `go vet ./...` and `golangci-lint run` are clean.
- `gofmt -l .` outputs nothing.
- The diff touches only the ticket's `Files`.

## Style
- Return errors, never panic. These parsers read untrusted input.
- Wrap errors with `fmt.Errorf("parsing X: %w", err)`.
- No `interface{}`/`any` in exported signatures.
- Malformed input is an error value, not a log line and not a zero value.

## Domain warnings
- Registry.pol strings are UTF-16LE, sizes are in BYTES, and Microsoft's
  public documentation of this format contains known errors. Follow the
  ticket's gotchas over any spec you recall.
- This project runs on LINUX in a container. There is no Windows API, no
  PowerShell, no WMI, no registry, no DPAPI, no UNC path you can os.Open.
  If a solution requires any of those, it is wrong — say so and stop.
- All SYSVOL access goes through an fs.FS. Never call os.Open or filepath
  helpers on a `\\server\share` path.
- Never silently drop a setting you cannot parse. Mark it unresolved and
  pass it through. Dropping data is worse than showing it raw.
- If a ticket's gotchas contradict your prior knowledge of Group Policy,
  the gotchas win. They were verified against the specification.
```

---

## Appendix B — Ticket prompt template

```
Ticket: <ID> — <title>

Implement exactly this contract:
<paste the Go signature>

Files you may modify: <list>
Do not modify any other file. Do not modify tests or fixtures.

The failing test is at <path>. Read it first — it is the specification.
Fixtures are at <path>.

ORACLE: <name + command>, threshold <N>%.
The oracle records what the real system does. If your implementation
disagrees with it, your implementation is wrong — including when you
are confident the specification says otherwise.

Gotchas — these contradict public documentation. They are correct:
<paste verbatim from the ticket>

Reference implementation excerpt (different language, do not copy structure):
<paste ~50 lines from adsys / PolicyPlus>

Done when: <Accept command> exits 0, <oracle command> meets threshold,
and `gofmt -l .` is empty.

If you fail twice, stop and tell me what the ticket is missing.
```

Keep the reference excerpt short. Pasting an entire file is the fastest way to burn the context this model needs for the actual work.

## Appendix C — Adversarial pass prompt (⚫ tickets only)

Run in a **fresh session**, with no memory of writing the implementation.

```
Below is a specification and a Go implementation claiming to satisfy it.
Your job is to find where they disagree. Assume there is at least one
defect — there usually is.

Specification:
<paste the ticket contract + gotchas + relevant PLAN.md section>

Implementation:
<paste the file>

For each issue: quote the exact line, state the input that triggers it,
and state the correct behaviour. Do not suggest style improvements.
Do not rewrite the code. Report only correctness disagreements.
```

This catches a specific failure the oracle can't: logic that is correct
on every topology the oracle happens to contain and wrong on a case it
doesn't. Cheap — one session per ⚫ ticket, roughly ten of them.

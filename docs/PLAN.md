# OpenGPM — Project Plan

**An open-source web UI replacement for the Group Policy Management Console.**

Working names: `opengpm`, `gpview`, `gpmc-web`. This document uses **OpenGPM**.

| | |
|---|---|
| **v1 scope** | Read-only: browse, inspect, report, model. No writes. |
| **Runtime** | **Docker container on Linux. No Windows anywhere at runtime, no domain join.** |
| **Stack** | Go backend, React + TypeScript frontend, SQLite cache |
| **Access** | LDAP/LDAPS + SMB3 direct, Kerberos keytab (LDAPS simple bind fallback) |
| **License** | Apache-2.0 (see §10) |
| **Target** | Windows Server 2016+ AD domains **and Samba AD DC** (both CI-tested) |
| **Windows** | Build/CI dependency only — generates fidelity fixtures (§9). Never required by users. |

---

## 1. Problem and goals

GPMC is an MMC snap-in. That means: Windows-only, RSAT install required, no remote access without RDP/jump box, one domain at a time, no shareable URLs, no diffing, no cross-domain search, and reports that are static HTML blobs. For an MSP or any team managing more than one forest, it is a bottleneck.

There is no *established* open-source, live-domain web GPMC alternative today. The commercial options (Adaxes, ManageEngine ADManager Plus, Netwrix, PolicyPak) are licensed per-admin or per-object.

Open-source prior art worth mining rather than duplicating:

- [GPOZaurr](https://github.com/EvotecIT/GPOZaurr) — PowerShell, static HTML hygiene reports. Validates demand and is an excellent catalog of health checks; not an interactive console.
- [Fleex255/PolicyPlus](https://github.com/Fleex255/PolicyPlus) — mature open-source ADMX/ADML parser plus POL reader/writer. **The best available reference model for §4.4**, and the first thing to read before writing the ADMX resolver.
- [ubuntu/adsys](https://github.com/ubuntu/adsys) — Canonical's Go implementation with a working PReg/`Registry.pol` parser. **The closest existing Go reference for §4.3.**
- [mirbach/Pretty-Policy-Analyzer](https://github.com/mirbach/Pretty-Policy-Analyzer) — small web app that browses and compares GPO *backups* without a DC. Closest thing to a direct precedent; different problem (offline backups vs. live domain).
- Samba's `libgpo` / `samba-tool gpo` — relevant to the §3.7 Samba target.

### v1 goals

1. **Browse** — forest/domain/OU/site tree, GPO inventory, links, WMI filters, delegation.
2. **Inspect** — render every setting a GPO contains, in GPMC-equivalent language, sourced from ADMX.
3. **Model** — compute effective policy for a given OU + security group set (Group Policy Modeling equivalent).
4. **Report** — health/hygiene checks, diff two GPOs or two points in time, export HTML/CSV/JSON.
5. **Search** — full-text across every setting in every GPO in every managed domain.

### Non-goals for v1

- Any write path into AD or SYSVOL. No create, edit, link, delete, backup/restore.
- Editing individual policy settings (GPME replacement).
- Intune / MDM / non-AD policy sources.
- Local Group Policy on non-domain machines.

### Explicit v2 candidates

Backup/restore, link/unlink, enable/disable, delegation edits, GPO templating, approval workflows, change-request diffs. Architecting for these in v1 (§3.5) is cheap; building them is not.

---

## 2. Why read-only first

- **Blast radius.** A bug in a read path shows a wrong number. A bug in a write path breaks authentication for 4,000 users. Trust has to be earned before write access is plausible.
- **Adoption.** A read-only tool can be pointed at production on day one with a service account that has only `Read` on the Policies container. That is a five-minute install decision, not a change-board decision.
- **The hard problem is reading anyway.** Faithfully rendering GPO contents and computing precedence is ~80% of the work. Writes reuse all of it.

---

## 3. Architecture

### 3.1 Deployment topology

```
┌──────────────────────────────────────────────────┐
│  Docker container  (scratch/distroless, ~30 MB)  │
│  Any Linux host. Not domain-joined.              │
│                                                  │
│   /opengpm  (single static binary, CGO_ENABLED=0)│
│   ├── HTTP server + embedded React SPA           │
│   ├── Collector (scheduled + on-demand)          │
│   ├── LDAP client   (go-ldap + gokrb5 GSSAPI)    │
│   ├── SMB3 client   (pure Go, see §3.2)          │
│   ├── Parsers (Registry.pol, ADMX, GPP, INF...)  │
│   ├── Precedence engine                          │
│   └── SQLite cache  (volume: /data)              │
│                                                  │
│  Mounts:  /etc/opengpm/krb5.keytab  (ro)         │
│           /etc/opengpm/ca.pem       (ro)         │
│           /data                     (rw)         │
└───────────┬──────────────────┬───────────────────┘
            │ LDAPS 636        │ SMB3 445
            │ (GSSAPI bind)    │ (Kerberos, signed)
            ▼                  ▼
      ┌──────────┐      ┌──────────────┐
      │  DC(s)   │      │  SYSVOL      │
      │  (GPC)   │      │  (GPT)       │
      └──────────┘      └──────────────┘
```

`docker run` with a keytab and a CA cert. No agent, no domain join, no privileged container, no host mounts of `//dc/sysvol`. Deploys equally well under Compose, Kubernetes, or a single `docker run`.

For the MSP multi-tenant case (§3.6): one container per managed forest, each holding exactly one keytab, all reporting to a central UI.

### 3.2 Transport: LDAP and SMB in pure Go

Everything is reimplemented from published specifications. There is no Windows API, no PowerShell, no `mount -t cifs`, and therefore no `CAP_SYS_ADMIN`.

**LDAP.** `github.com/go-ldap/ldap/v3` for the protocol; `github.com/jcmturner/gokrb5` for GSSAPI/SPNEGO bind from a keytab. Fallback is simple bind over LDAPS with a service account password (§5). DC discovery via `_ldap._tcp.dc._msdcs.<domain>` SRV records.

**SMB.** Resolved by the T-00 spike ([docs/SPIKE-T00.md](SPIKE-T00.md)): **verdict GO** — pure-Go SMB over Kerberos is proven from a hardened container (signing required, SMB3 encryption, NTLM denied), so the `cifs`-mount fallback is not needed. The chosen library for T-03 is [`CloudSoda/go-smb2`](https://github.com/CloudSoda/go-smb2): it uses `jcmturner/gokrb5/v8` — the same stack the LDAP path needs — so one keytab, one TGT, one clock-skew path, and it provides a `Share.DirFS()` `fs.FS`. [`jfjallid/go-smb`](https://github.com/jfjallid/go-smb) (SMB3, active mid-2026) passed the spike unmodified and is the proven fallback; it ships its own gokrb5 fork (a second Kerberos stack) and no `fs.FS`. `hirochachacha/go-smb2` is rejected: it has no `Krb5Initiator` (CloudSoda's fork added that) and its `Initiator` methods are unexported, so none can be added out of tree; dead since 2022-07.

> **Phase 0 spike — done, verdict GO** ([docs/SPIKE-T00.md](SPIKE-T00.md)). The SMB library was picked by testing against a real DC with **SMB signing required** (the default for SYSVOL/NETLOGON) and SMB3 encryption enabled, authenticating by **Kerberos, not NTLM** — NTLM is disabled outright in many hardened domains. The pure-Go path worked, so the `cifs`-mount fallback in a privileged container (a materially worse product) is not needed.

**What is deliberately lost:** `Get-GPOReport` as a live cross-check and `gpresult /x` ingestion. Both are Windows-only. See §9 — the fidelity harness survives by moving to CI, and §6.4 loses the live-RSoP feature.

**What is gained:** trivial deployment, no domain join, no Windows licence in the loop, a contributor base that doesn't need a Windows VM to build, and Samba AD DC support (§3.7) as a first-class target rather than a someday.

### 3.3 Collector pipeline

```
LDAP sweep ──┐
             ├──► normalize ──► parse ──► resolve ──► SQLite ──► API
SYSVOL walk ─┘                            (ADMX)
```

1. **LDAP sweep.** Enumerate `groupPolicyContainer` objects under `CN=Policies,CN=System,<domain DN>`. Enumerate `organizationalUnit`, `domainDNS`, and site objects for `gPLink` / `gPOptions`. Enumerate `msWMI-Som` under `CN=SOM,CN=WMIPolicy,CN=System`.
2. **SYSVOL walk.** For each GPO, read `gPCFileSysPath` and walk the GPT directory **over SMB**. Note that `gPCFileSysPath` is a UNC path (`\\domain\SysVol\...`) — it must be translated to an SMB share plus path, and the `\\domain\` form requires DC resolution rather than being a literal host.
3. **Parse.** Every file format below into a common `Setting` record.
4. **Resolve.** Join raw registry values against the ADMX catalog to produce human-readable policy names, categories, states, and element values.
5. **Persist.** Content-addressed: hash each parsed artifact, only re-parse when `versionNumber` / `GPT.INI` version / file mtime changes. Full sweep of a 500-GPO domain should complete in under 60s; incremental in under 5s.
6. **Snapshot.** Every sweep is retained as an immutable snapshot, which is what makes point-in-time diff (§6.5) free.

### 3.4 Package layout

```
cmd/opengpm/              main, CLI, config
internal/transport/
  ├── krb/                keytab, TGT lifecycle, clock-skew handling
  ├── ldapx/              go-ldap + GSSAPI bind, SRV discovery, SD flags
  └── smbx/               SMB3 client wrapper, UNC translation
internal/directory/       LDAP queries, schema, SOM tree, SD parsing
internal/sysvol/          GPT traversal over SMB, file discovery
internal/parse/
  ├── regpol/             Registry.pol (MS-GPREG)
  ├── admx/               ADMX/ADML catalog + resolver
  ├── secedit/            GptTmpl.inf security templates
  ├── gpp/                Group Policy Preferences XML (21 types)
  ├── scripts/            scripts.ini, psscripts.ini
  ├── fdeploy/            folder redirection
  ├── audit/              audit.csv (advanced audit policy)
  └── comment/            comment.cmtx
internal/model/           canonical GPO / Setting / Link / SOM types
internal/precedence/      inheritance + filtering engine
internal/report/          health checks, diff, exporters
internal/store/           SQLite, snapshots, FTS5 index
internal/api/             REST handlers, auth middleware
internal/collect/         orchestration, scheduling
web/                      React + TS + Vite (embedded via go:embed)
testdata/                 golden GPO fixtures + expected output
```

### 3.5 Designing for future writes

Even though v1 never writes, three decisions keep the door open cheaply:

- All directory access goes through a `directory.Reader` interface. A `directory.Writer` can be added beside it without touching call sites.
- The canonical `model.GPO` is a complete, round-trippable representation — enough to re-serialize a `Registry.pol`, not just describe one.
- Every API mutation-shaped concept (link order, GPO status) is modeled as data, not derived on the fly.

### 3.6 Multi-domain / multi-tenant

The store is keyed by `(tenant_id, domain_id, ...)` from day one. A single UI can front many collectors; each collector holds credentials for exactly one forest and pushes snapshots over an authenticated channel. For a single-domain user this is invisible — one implicit tenant.

### 3.7 Samba AD DC — a first-class target

Because nothing in the stack is Windows-specific, Samba-based domains work through the same code paths. **Samba is in the CI matrix alongside Windows AD, not a best-effort afterthought.**

This is strategically the most interesting part of the pivot. Samba AD DC has full GPO support and **no GPMC at all** — administrators currently manage policy there with `samba-tool gpo` and hand-edited XML. For that audience OpenGPM isn't a nicer alternative to an existing tool; it's the only graphical option in existence. Expect the earliest and most enthusiastic adopters here.

Practical differences to handle: Samba's SYSVOL layout and ACL semantics differ subtly (the `sysvolreset`/`sysvolcheck` divergence is a known pain point and a natural health check), and some AD attributes Windows always populates may be absent. Both CI targets run the same test suite; divergences get explicit skips with a documented reason, never silent branching.

---

## 4. The data model (the hard part)

This section is the actual engineering risk. Everything else is a web app.

### 4.1 Group Policy Container (AD side)

`groupPolicyContainer` attributes to capture:

| Attribute | Meaning |
|---|---|
| `cn` | `{GUID}` — the GPO identity |
| `displayName` | friendly name (not unique!) |
| `gPCFileSysPath` | UNC path to the GPT |
| `versionNumber` | packed DWORD: high 16 bits = user version, low 16 = computer version |
| `flags` | 0 = enabled, 1 = user config disabled, 2 = computer config disabled, 3 = both |
| `gPCMachineExtensionNames` | CSE GUIDs — which extensions must process this GPO |
| `gPCUserExtensionNames` | same, user side |
| `gPCWQLFilter` | linked WMI filter reference |
| `gPCFunctionalityVersion` | required reading per MS-GPOL; anything other than `2` is itself a health signal |
| `nTSecurityDescriptor` | security filtering + delegation |
| `whenCreated` / `whenChanged` | lifecycle |

**Not all settings live in the GPC attributes or SYSVOL.** Some are stored as **AD child objects of the GPC** and a naive "attributes + SYSVOL walk" collector will silently miss them:

- Wireless (802.11) and wired (802.3) policies — `ms-net-ieee-80211-GroupPolicy` / `ms-net-ieee-8023-GroupPolicy` objects (MS-GPWL).
- Software installation — `packageRegistration` objects under `CN=Packages,CN=Class Store,CN=Machine,<GPO DN>`.

**Version mismatch detection.** Compare `versionNumber` against `GPT.INI`'s `Version=` value. A mismatch means AD and SYSVOL are out of sync — a genuine, common, hard-to-spot problem GPMC surfaces poorly. First-class health check.

> **Pin both reads to the same DC.** LDAP goes to one DC while `\\domain\SYSVOL` may resolve to another; with replication lag this produces false "out of sync" alerts on the flagship check. Bind LDAP and SMB to the same specific DC — or the PDC emulator, matching `Get-GPO`'s behavior.

### 4.2 Links and the SOM tree

`gPLink` on a domain, OU, or site object is a concatenated string:

```
[LDAP://cn={GUID},cn=policies,cn=system,DC=corp,DC=local;0][LDAP://...;2]
```

The trailing integer (`gPLinkOptions`) is a flag: `0` = enabled and not enforced, `1` = link disabled, `2` = enforced, `3` = disabled *and* enforced. Note that MS-GPOL 2.2.2 specifies `3` behaves identically to `1` — the link is **ignored** and enforcement does not apply. Render it as disabled, not as an enforced link.

**Ordering — get this right.** The **first** entry in the `gPLink` string is Link Order 1 and has the **highest** precedence. The reversal that trips people up is between string order and *application* order, not precedence: per MS-GPOL 3.2.5.1.5, non-enforced links are *prepended* to the GPLink list as the string is walked, so the first string entry is applied last and therefore wins. `New-GPLink` confirms the same convention from the other direction — a new link defaults to "the lowest precedence with a link order equal to the number of GPO links to the container, plus one," i.e. appended to the end of the string.

> Be aware that a widely-copied PFE script (`GP_Link_Report.ps1`) computes precedence as `$links.count - $i` — the opposite — and several blog posts repeat it. Implement per the spec, and verify empirically against GPMC's Modeling wizard in the Phase 0 test domain. This gets a dedicated test.

Two more traps: the **same GPO may be linked more than once to the same SOM**, each link with independent `gPLinkOptions` (MS-GPOL 2.2.2) — so links must not be keyed by GPO GUID. And `gPLink` entries may reference **GPOs in other domains**; site links live in the Configuration NC. The collector must group GPO DNs by domain and rebind, per the GPO Search algorithm.

`gPOptions = 1` on a container means **block inheritance**.

### 4.3 Registry.pol — `MS-GPREG`

Located at `<GPT>\Machine\Registry.pol` and `<GPT>\User\Registry.pol`.

- **Header**: 8 bytes — `PReg` (signature `0x67655250`) followed by a little-endian DWORD version, currently `1`.
- **Body**: a sequence of records, each literally `[key;value;type;size;data]` where the brackets and semicolons are UTF-16LE characters. `key` and `value` are null-terminated UTF-16LE strings, `type` and `size` are LE DWORDs, and `data` is `size` bytes.

**Warning:** Microsoft's own [Registry Policy File Format](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format) page contains errors; Aaron Margosis published [corrections](https://aaron-margosis.medium.com/corrections-to-microsoft-documentation-about-the-registry-policy-file-format-f6cb0caa9a80) that the implementation should follow. [MS-GPREG](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/25a5b25b-e81e-41b2-9321-9635ea44ab70) is the normative source. Cross-check against [`GPRegistryPolicyParser`](https://github.com/PowerShell/GPRegistryPolicyParser) (MIT, Microsoft) as a reference implementation.

**Special value prefixes** encode deletion semantics and must be handled or settings will render wrong:

`**del.<value>`, `**delvals.` / `**DelVals`, `**DeleteValues`, `**DeleteKeys`, `**soft.<value>`, `**SecureKey`, `**Comment:`

Per-prefix notes, mostly from Margosis's corrections:

- `**Comment:` is **undocumented by Microsoft** but is emitted by Windows in real `.pol` and `ntuser.pol` files. A parser that doesn't special-case it will render comments as bogus settings.
- For `**DeleteKeys`, the *key* field is **ignored** and may be empty; the actual key paths live in *data* as a semicolon-delimited, null-terminated UTF-16LE string. Microsoft's page states the opposite.
- `**SecureKey` is inert on Windows 7 SP1 and later. Do not render it as an effective setting.
- Match prefixes **case-insensitively** and accept `**delvals.` both with and without the trailing period — Microsoft documents one form, real tooling emits the other.

### 4.4 ADMX / ADML catalog

Registry.pol contains registry paths. GPMC shows "Turn off Windows Defender Antivirus." The bridge is the ADMX catalog. There is **no mature Go ADMX parser** — this must be written. It is well-scoped work: `encoding/xml` plus careful semantics.

Must handle: `<policy>` with `class` (Machine/User/Both), `<parentCategory>` chains, `<supportedOn>` references, `enabledValue`/`disabledValue`, `enabledList`/`disabledList`, and `<elements>` — `text`, `decimal`, `boolean`, `enum`, `list`, `multiText`. List elements with `explicitValue` and prefix-numbered keys are the fiddly part.

**Running off-Windows changes this materially.** There is no local `C:\Windows\PolicyDefinitions` to fall back on, so catalog sourcing becomes a first-class product problem rather than an afterthought:

1. The domain's **Central Store** (`\\domain\SYSVOL\domain\Policies\PolicyDefinitions`), read over SMB. Best case — it's the domain's own authoritative set.
2. An **admin-supplied volume mount** (`/etc/opengpm/policydefinitions`). The documented path for domains with no Central Store: copy the folder off any Windows box once.
3. A **fetched catalog**, downloaded on first run from Microsoft's published ADMX packages into `/data/admx/<release>/`, pinned by version and checksum.

Licensing forces this shape: Microsoft's ADMX files **cannot be vendored into the repo** (§10). The container therefore ships with no catalog at all and must acquire one. Make this loud and obvious in first-run setup — "no ADMX catalog configured, settings will render as raw registry paths" is a legitimate degraded state, but it must never be a silent one.

Language: prefer `en-US` ADML, fall back to any available, surface unresolved strings as raw registry paths rather than failing.

**Orphaned settings** — registry values with no matching ADMX policy — must be shown, not hidden. GPMC labels these "Extra Registry Settings," and they are a frequent source of confusion. Rendering them clearly is an immediate differentiator.

### 4.5 Everything else in the GPT

| Path | Format | Parser |
|---|---|---|
| `GPT.INI` | INI | version sync check |
| `\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` | INI (UTF-16) | account/audit/user-rights/services/registry/file ACLs |
| `\Machine\Microsoft\Windows NT\Audit\audit.csv` | CSV | advanced audit policy |
| `\{Machine,User}\Preferences\<Type>\<Type>.xml` | XML | GPP types (Drives, Printers, Registry, Shortcuts, Scheduled Tasks, Local Users & Groups, ...) incl. item-level targeting |
| `\{Machine,User}\Scripts\scripts.ini`, `psscripts.ini` | INI | startup/shutdown/logon/logoff |
| `\User\Documents & Settings\fdeploy1.ini` | INI | folder redirection, MS-GPFR Version One — **clients try this first** |
| `\User\Documents & Settings\fdeploy.ini` | INI | folder redirection, Version Zero fallback |
| `\Machine\Applications\*.aas` | binary | software installation (best-effort; low priority) |
| `comment.cmtx` | XML | per-setting admin comments |

**GPP item-level targeting** deserves attention: it is a nested boolean tree of filters (OS, group membership, IP range, WMI query, ...) that GPMC renders poorly. A clean tree view here is a real win.

> Microsoft's docs say "20 client-side extensions" but the list omits Services; enumerating actual `Preferences\<Type>\` folders yields 21. Discover types from the filesystem rather than hardcoding a count.

### 4.6 Security filtering and delegation

Parse `nTSecurityDescriptor` into ACEs. Security filtering = principals holding both `Read` and the **Apply Group Policy** extended right, GUID `edacfd8f-ffb3-11d1-b41d-00a0c968f939`. Delegation = the remaining rights on the GPC, plus the NTFS ACL on the GPT.

**Reading the SD requires the LDAP SD flags control** (`LDAP_SERVER_SD_FLAGS_OID`, `1.2.840.113556.1.4.801`). Without it, a low-privilege account gets `nTSecurityDescriptor` **silently omitted** — because reading the SACL needs `SeSecurityPrivilege`. Request DACL+Owner+Group only. This is a `go-ldap` implementation detail that directly affects the §5 least-privilege claim, and it fails quietly, which is the worst kind.

**MS16-072 / KB3163622.** Since June 2016, *user* GPOs are retrieved in the **computer's** security context. Filtering analysis must therefore evaluate the computer account's token for user-side GPOs as well. "User GPO filtered to a user group, but Authenticated Users / Domain Computers lacks Read" is one of the most common real-world breakages in existence and belongs in the §6.6 checks.

Health check: GPC ACL and GPT ACL disagreeing is a known, silent breakage mode.

### 4.7 Precedence engine

Given a target OU (and optionally a set of security groups, a WMI-evaluable machine profile, and a site), compute the ordered, effective policy set:

1. Walk the SOM chain: **Local → Site → Domain → OU → nested OUs**.
2. At each level, order links by link order (per §4.2 — first in string wins).
3. Apply **block inheritance** (`gPOptions=1`) — drops everything from above *except* enforced links.
4. Apply **enforced** links — these override, and higher-in-the-tree enforced links win over lower ones (the inversion of the normal rule).
5. Drop GPOs whose `flags` disable the relevant half.
6. Drop GPOs the target does not pass security filtering for.
7. Drop GPOs whose WMI filter does not match (evaluated against a supplied machine profile, or flagged "unevaluated").
8. **Apply loopback processing** if any applicable computer GPO enables it — in *Replace* mode, discard the user's own OU-derived user settings entirely and substitute those from the computer's SOM chain; in *Merge* mode, process the user's list first and then the computer's, with the computer's winning.
9. Merge settings; last writer wins; record the losers.

**Loopback is not optional.** It changes which user GPOs apply based on the computer's OU, and it is used precisely in the environments where people most need modeling — RDS, VDI, kiosks, shared workstations. A modeling feature that ignores loopback will be confidently wrong exactly where it matters most. GPMC's Modeling wizard has a loopback toggle; so must this.

Output must retain **every** contributing GPO per setting, with the winner marked — mirroring the RSoP `precedence` semantics where `precedence = 1` is the applied instance. Showing *why* a setting lost is the single most valuable thing this tool can do, and GPMC does it badly.

This engine gets a dedicated table-driven test suite with hand-built topologies. It is the highest-risk component.

---

## 5. Security model

Read-only does not mean harmless — GPO contents disclose the entire security posture of a domain. Running off-domain in a container changes several of these answers.

- **Service account**: a plain domain user with `Read` on the Policies container, OUs/sites, WMI filter container, and SYSVOL. **gMSA is no longer available** — retrieving a gMSA password requires a domain-joined machine. This is a real regression from the Windows design and should be stated plainly in the docs; compensate with a short-lived keytab and documented rotation.
- **Credentials**: Kerberos **keytab** mounted read-only, ideally as a Docker/Kubernetes secret rather than a bind mount. Fallback is a service account password over LDAPS, supplied by env var or secret file — never baked into the image, never in `docker-compose.yml` committed to a repo.
- **No DPAPI substitute.** Nothing sensitive is persisted by the app; the keytab is the only secret and the platform owns it. If a future feature needs at-rest encryption, that's an explicit design decision, not an ambient capability.
- **Clock skew**: Kerberos fails beyond ~5 minutes of drift, and containers inherit host clock problems. Detect skew explicitly at startup and emit a specific, actionable error — not a generic auth failure. This will otherwise be the single most common support issue.
- **Never store domain admin credentials.** Refuse to start if the principal is in Domain Admins, with an override flag and a loud warning.
- **Admin authentication**: **OIDC is now the primary** (Negotiate SSO from a non-domain-joined container is awkward at best). Support Kerberos SPNEGO for browsers where the environment allows it. No local password database.
- **Authorization**: role-based — Viewer, Auditor (can export), Admin (can configure collectors). Optionally scope a role to specific OUs or tenants.
- **Transport**: HTTPS mandatory (terminate at a reverse proxy or supply a cert), LDAPS with a mounted CA bundle, **SMB signing required and SMB3 encryption preferred** — never negotiate down. Refuse plaintext LDAP entirely.
- **Container hardening**: distroless or scratch base, non-root UID, read-only root filesystem, no added capabilities, `no-new-privileges`. If the `cifs`-mount fallback (§3.2) is ever needed it breaks all of this, which is a further reason to prove the pure-Go SMB path in Phase 0.
- **Audit log**: append-only record of every view and export, with the user, tenant, and object. Auditors will ask.
- **Supply chain**: `govulncheck` and `npm audit` in CI, signed images (cosign), SBOM published per release, pinned base image digests.
- Ship a `opengpm doctor` subcommand that checks DNS/SRV resolution, clock skew, keytab validity, LDAP bind, SMB access, and effective permissions — replacing the Windows-only `Test-OpenGPMPermissions` script.

---

## 6. Feature surface

### 6.1 Console (the GPMC-equivalent core)

Forest → domain → OU tree with GPO links; GPO inventory list with sortable columns (name, status, version, links, last modified, owner); per-GPO tabs mirroring GPMC — Scope, Details, Settings, Delegation — so existing muscle memory transfers. Deep-linkable URLs for every object, which GPMC simply cannot do.

### 6.2 Settings viewer

Full rendered settings tree, ADMX-resolved, with the raw registry path always one click away. Collapse/expand, "show only configured," per-setting comments, and a clearly labeled Extra Registry Settings section.

### 6.3 Global search

SQLite FTS5 over policy names, registry paths, values, GPO names, and comments across all managed domains. Answers questions that currently require a script: *which GPO sets this registry key?* *where is this drive mapping defined?* *what references this file server?* — the last one being invaluable during a server migration.

### 6.4 Modeling and results

- **Modeling**: pick an OU, optionally add security groups and a machine profile → full effective policy with per-setting winner/loser breakdown. Pure computation, no client required. **This is now the only RSoP path**, which raises the stakes on the §4.7 engine considerably.
- **Results (v2)**: `gpresult /x` ingestion is Windows-only and drops out of v1. It returns as an *upload* — paste or upload `gpresult /x` XML produced elsewhere, and diff it against our modeled result. That keeps the ground-truth check without putting Windows in the runtime path, and fits an RMM that can run `gpresult` on demand and post the output.

### 6.5 Diff

Three modes, all built on the same snapshot machinery: GPO A vs GPO B; one GPO across two snapshots (what changed last Tuesday); entire domain across two snapshots. Side-by-side and unified views, exportable.

### 6.6 Health and hygiene reports

Port the well-established checks (GPOZaurr is a good catalog to mine):

- Empty GPOs; unlinked GPOs; GPOs linked only to disabled links
- **MS16-072 breakage**: user GPO filtered to a user group without Read for Authenticated Users / Domain Computers
- AD/SYSVOL version mismatch
- `gPCFunctionalityVersion` ≠ 2
- GPC/GPT ACL divergence; broken or missing GPT folders
- Non-default GPO owners; GPOs owned by deleted SIDs
- Settings configured but the corresponding half disabled by `flags`
- Duplicate `displayName` values
- Orphaned SYSVOL folders with no GPC
- Missing/unresolvable ADMX definitions
- Broken WMI filter references; unlinked WMI filters
- Legacy/deprecated settings and dead file-server references in GPP
- Settings overridden everywhere they apply (configured but never effective)

Each check: severity, plain-English explanation, affected objects, and remediation guidance. The guidance is text in v1 — the button comes in v2.

### 6.7 Export

HTML (self-contained, GPMC-report-comparable), CSV, JSON, and a stable REST/JSON API so the whole thing is scriptable.

---

## 7. Frontend

React 18 + TypeScript + Vite, embedded into the Go binary via `go:embed`. TanStack Query for server state, TanStack Table for the dense grids, TanStack Virtual for the settings trees (a large GPO has thousands of nodes and must not jank). Tailwind + shadcn/ui for a neutral, accessible baseline. Dark mode, keyboard navigation, and WCAG 2.1 AA as requirements rather than polish — this is a tool people stare at for hours.

OpenAPI spec generated from the Go handlers; TypeScript client generated from the spec. No hand-written API types.

---

## 8. Roadmap

Estimates assume one full-time engineer. Halve for two, roughly.

### Phase 0 — Spike (2–3 weeks)

De-risk the unknowns before committing to the architecture. Stand up **two** test domains — Windows AD and Samba AD DC — with deliberately gnarly OU structures. Read `PolicyPlus` and `adsys` first; both solve pieces of this already.

**Spike 0a — SMB over Kerberos from Linux. Do this first; everything else depends on it.** From a container, authenticate to a DC by Kerberos (NTLM disabled), with **SMB signing required** and SMB3 encryption on, and read a file out of SYSVOL. Try `jfjallid/go-smb`, `CloudSoda/go-smb2`, and `hirochachacha/go-smb2` in that order. If all three fail, the whole Docker architecture is in question and you need to know in week one, not month three.

**Spike 0b — LDAP GSSAPI bind from a keytab**, including SRV-record DC discovery and the `LDAP_SERVER_SD_FLAGS_OID` control (§4.6) returning a usable `nTSecurityDescriptor` as a non-admin.

**Spike 0c — parsing.** Parse a real `Registry.pol` and match `Get-GPOReport` output; parse `PolicyDefinitions` and resolve 20 known policies to their GPMC display names; read GPC + `gPLink` over LDAP.

**Settle the link-order question empirically here** (§4.2): create three links on one OU via the GPMC GUI, dump the raw `gPLink` string, and compare against GPMC's reported Link Order and Modeling output. The spec and a popular script disagree; resolve it before any precedence code is written.

**Exit criteria:** SMB-over-Kerberos proven from a container against a signing-required DC; and a CLI that dumps one GPO's settings and matches GPMC's rendering by eye.

### Phase 1 — Inventory (M1, ~6 weeks)

Transport layer (Kerberos, LDAP, SMB), LDAP collector, SYSVOL walker over SMB, SQLite store with snapshots, REST API skeleton, React shell with tree + GPO list + Scope/Details tabs, and a working `docker run`. No settings rendering yet.

*(One week longer than the Windows design — the transport layer is real work that `os.ReadFile` over a UNC path gave away for free.)*

**Ship it.** An installable binary that lists GPOs and links in a browser is already useful, and early feedback is worth more than a fourth month of solo work.

### Phase 2 — Settings (M2, ~8 weeks)

The big one. `Registry.pol` parser, ADMX/ADML catalog and resolver plus the three-tier catalog sourcing (§4.4), `GptTmpl.inf`, GPP XML for all types, scripts, folder redirection, audit CSV, comments. Full settings tree UI. Every parser reads through an `fs.FS`, so this entire phase is testable offline against a local directory — the SMB transport is invisible to it.

**Exit criterion:** ≥99% setting-level agreement with GPMC on a 200-GPO corpus, with every discrepancy triaged.

### Phase 3 — Precedence and modeling (M3, ~5 weeks)

Precedence engine, security filtering via SD parsing, WMI filter representation, modeling UI with winner/loser breakdown. No `gpresult` fallback exists now, so the engine must stand on its own — weight the test budget accordingly.

### Phase 4 — Reports and diff (M4, ~4 weeks)

Health check framework and initial ~15 checks, snapshot diff engine, diff UI, HTML/CSV/JSON export.

### Phase 5 — Search and multi-domain (M5, ~3 weeks)

FTS5 index and search UI, multi-domain/tenant collectors, RBAC, audit log.

### Phase 6 — 1.0 (~4 weeks)

Published container images (multi-arch amd64/arm64), Compose and Helm examples, `opengpm doctor`, documentation site with a first-run guide covering keytab creation and DNS, cosign-signed images and SBOM, security review, performance pass against a 2,000-GPO domain.

**Total to 1.0: roughly 7–8 months solo, 4 months for two.** M1 is usable at ~2.5 months.

---

## 9. Testing

- **Golden fixtures.** A `testdata/` corpus of real (sanitized) `Registry.pol`, `GptTmpl.inf`, and GPP files with expected parse output. Every parser bug becomes a fixture.
- **Fidelity harness — now a two-stage, offline design.** Still the critical test, but Windows moves out of the runtime and into a *fixture generation* step:

  **Stage 1 (occasional, Windows required).** A Windows VM runs `Get-GPOReport -ReportType Xml` across a corpus of GPOs, plus a copy of the corresponding SYSVOL bytes. Both are normalized and **committed to the repo** as golden fixtures. Run this when the corpus grows, not on every build.

  **Stage 2 (every CI run, Linux only).** Parse the committed SYSVOL bytes with our own code, normalize, and assert equivalence against the committed GPMC output. Pure Go, no Windows, runs anywhere.

  This is strictly better than the original design for a contributor's purposes: anyone can run the full fidelity suite on a laptop with no Windows licence, and the pass rate is still the project's headline credibility metric (§10). The cost is that the corpus goes stale unless someone periodically re-runs Stage 1 — assign that to a release checklist item.

- **Dual-target integration suite.** Every integration test runs against **both** a Windows AD DC and a Samba AD DC (§3.7) in CI. Divergences get explicit, documented skips — never silent branching.
- **Transport tests.** SMB signing required, SMB3 encryption, Kerberos-only (NTLM disabled), expired TGT renewal, and deliberate clock skew. These are the new failure modes the Windows design didn't have, and they fail in production, not in unit tests.
- **Precedence oracle.** Rather than hand-constructed tests alone, generate ~200 randomized topologies (OU depth, link counts, enforced/disabled flags, block inheritance, filtering, loopback merge/replace), run GPMC's own Group Policy Modeling against each, and commit its answers as fixtures. **GPMC becomes the specification for the precedence engine**, and "subtly wrong precedence" — the top correctness risk in §11 — turns into a measurable agreement percentage that must hit 100%.

  Supplement with hand-built adversarial cases: enforced-above-blocked, enforced-vs-enforced at different depths, the same GPO linked twice to one SOM, `gPLinkOptions=3`, loopback replace with the computer in a different tree.

- **ADMX differential testing.** Drive `PolicyPlus` headlessly over the same ADMX catalog and `Registry.pol` inputs and diff its rendering against ours. Targets the `<elements>` semantics (§4.4) that hand-written tests systematically miss.
- **Fuzzing.** `go-fuzz` on every binary/INI/XML parser. These consume attacker-influenceable input from SYSVOL; malformed input must never panic the service.
- **Property test.** Parse → serialize → parse round-trips to a fixed point for `Registry.pol`. Free, and validates the write path long before writes exist.
- **Load test.** Synthetic 2,000-GPO / 5,000-OU domain generator; assert full sweep and modeling stay within budget.
- **E2E.** Playwright over the main flows.

---

## 10. Licensing and community

**Apache-2.0.** Permissive enough for enterprise legal review to wave through, with an explicit patent grant that MIT lacks — relevant when reimplementing documented Microsoft protocols. (AGPL would deter exactly the corporate users this needs; a permissive license maximizes contribution from admins at companies that forbid copyleft.)

Legal footing: MS-GPREG and the ADMX schema are published under Microsoft's Open Specification Promise. Do not vendor Microsoft's ADMX files into the repo — read them from the host or Central Store at runtime, and let the fallback bundle be a separate, clearly-licensed download.

Community mechanics: a public test-domain builder script so contributors can reproduce issues; parsers structured so adding a GPP type is a self-contained PR; health checks as a plugin-ish registry so a new check is one file; conventional commits and semantic versioning; a published fidelity score as the project's headline credibility metric.

---

## 11. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **No viable pure-Go SMB client for Kerberos + required signing** | Architecture-breaking — forces a privileged container with a `cifs` mount | **Spike 0a in week one**, three candidate libraries. Treat as a go/no-go gate on the whole Docker design |
| **Kerberos operational friction** — clock skew, SRV/DNS, keytab rotation, SPN mismatches | Users can't get past first run; support burden dominates | Explicit skew and DNS checks at startup with specific errors; `opengpm doctor`; LDAPS password fallback as an escape hatch; a genuinely good first-run doc |
| **No ADMX catalog available** (no Central Store, no Windows to copy from) | Settings render as raw registry paths — looks broken | Three-tier sourcing (§4.4); fetch-on-first-run; loud, explicit degraded-state banner rather than silent ugliness |
| Loss of live `Get-GPOReport` cross-check | Weaker correctness signal than the Windows design had | Two-stage offline harness (§9) — arguably better, since contributors can run it without Windows; add a release-checklist item to refresh the corpus |
| Samba divergence doubles integration surface | CI complexity, flaky tests | Same suite both targets, explicit documented skips; Samba is also the strategic wedge (§3.7), so the cost buys something |
| Parser fidelity gaps vs. GPMC | Loss of trust — the whole value proposition | Fidelity harness in CI; publish the score; label anything unparsed as "unrecognized," never silently drop |
| ADMX resolution complexity underestimated | M2 slips badly | Spike it in Phase 0; accept graceful degradation to raw registry paths |
| Precedence engine subtly wrong | Users make bad decisions from bad data — **and there's no `gpresult` safety net now** | Heavy table tests; dual-target (Windows + Samba) integration runs; label modeling results as advisory in v1; prioritize the v2 `gpresult` XML *upload* comparison (§6.4) to recover ground truth |
| Undocumented/legacy formats (`.aas`, IE Maintenance) | Incomplete coverage | Explicitly out of scope, clearly surfaced in UI as "not rendered" |
| Read-only limits adoption ("nice, but I still open GPMC") | Slow uptake | Lead with what GPMC *can't* do: search, diff, multi-domain, shareable links |
| Security scrutiny of a tool that aggregates all policy data | Blocked by security teams | Least-privilege by default, audit log, published threat model, third-party review before 1.0 |
| Solo-maintainer burnout | Project stalls | Ship M1 early for feedback; keep the contribution surface (parsers, checks) low-friction |

---

## 12. Immediate next steps

1. **Run Spike 0a — SMB over Kerberos from a Linux container against a signing-required DC.** Everything else is contingent on this. Do it before writing a line of product code.
2. Stand up both test domains — Windows AD and Samba AD DC — with deliberately messy OU trees and ~50 GPOs covering every setting category.
3. Run Spikes 0b and 0c; specifically confirm the ADMX resolver effort estimate.
4. Pick and register the name; create the repo with Apache-2.0, CoC, and contribution guide.
5. Write the fidelity harness *before* the real parsers — it defines "done" for Phase 2.
6. Publish the plan as a GitHub Discussion. The Samba angle (§3.7) is the strongest hook — that community has no graphical option at all, and is where the first real users are.

---

## Sources

- [MS-GPREG: Registry Policy Application Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/25a5b25b-e81e-41b2-9321-9635ea44ab70)
- [MS-GPOL 3.2.5.1.5 — GPO Search (link ordering)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/5c7ecdad-469f-4b30-94b3-450b7fff868f)
- [MS-GPOL 2.2.2 — gPLink / gPLinkOptions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/08090b22-bc16-49f4-8e10-f27a8fb16d18)
- [MS-GPOL 3.3.5.7 — GPO Link Creation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/8333c5ba-8b41-4dfe-9c53-6911026a11f3)
- [MS-GPWL — Wireless/Wired Group Policy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpwl/c5c240dc-de98-4219-b3f1-3b3dc797b642)
- [Deploying Group Policy Security Update MS16-072 / KB3163622](https://learn.microsoft.com/en-us/archive/blogs/askds/deploying-group-policy-security-update-ms16-072-kb3163622)
- [New-GPLink (link order / precedence semantics)](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gplink)
- [Registry Policy File Format (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format)
- [Corrections to Microsoft documentation about the Registry Policy File Format — Aaron Margosis](https://aaron-margosis.medium.com/corrections-to-microsoft-documentation-about-the-registry-policy-file-format-f6cb0caa9a80)
- [PowerShell/GPRegistryPolicyParser](https://github.com/PowerShell/GPRegistryPolicyParser)
- [Get-GPOReport (GroupPolicy module)](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gporeport)
- [Group Policy Management Console (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-management-console)
- [RSOP_PolicySetting class](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-policysetting)
- [gpresult](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult)
- [EvotecIT/GPOZaurr](https://github.com/EvotecIT/GPOZaurr)
- [Fleex255/PolicyPlus](https://github.com/Fleex255/PolicyPlus) — ADMX/ADML parser reference
- [ubuntu/adsys](https://github.com/ubuntu/adsys) — Go PReg parser reference
- [mirbach/Pretty-Policy-Analyzer](https://github.com/mirbach/Pretty-Policy-Analyzer)
- [Managing Group Policy ADMX Files Step-by-Step Guide](https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb530196(v=msdn.10))
- [go-ldap/ldap](https://github.com/go-ldap/ldap)

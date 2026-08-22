# T-00 — SMB over Kerberos from a container (spike outcome)

Verdict: GO. SYSVOL is readable from a non-root, cap-drop=ALL,
read-only scratch container, authenticated by Kerberos from a
keytab, against a DC that requires SMB signing, requires SMB3
encryption, and denies NTLM. The cifs-mount fallback (PLAN §3.2) is
not needed; the §5 container-hardening claims hold.

## Library results
- jfjallid/go-smb — PASS unmodified. SMB 3.1.1, signing required,
  AES-128-CCM, Kerberos AP-REQ. Ships its own gokrb5 fork (a second
  Kerberos stack) and a large offensive-security surface; no fs.FS.
  Kept as the proven fallback.
- cloudsoda/go-smb2 — CHOSEN for T-03. SMB layer works (SMB 3.1.1,
  AES-128-GCM, Kerberos). Uses jcmturner/gokrb5/v8 — the SAME stack
  go-ldap needs — so one keytab, one TGT, one clock-skew path.
  Provides Share.DirFS() fs.FS (T-03's contract) and cloudsoda/sddl
  for D-06/S-01.
- hirochachacha/go-smb2 — FAIL, structural. It has NO Krb5Initiator
  (CloudSoda's fork added that; PLAN §3.2 is wrong) and its
  Initiator methods are unexported, so none can be added out of
  tree. Dead since 2022-07. Remove as a candidate.

## Keytab KVNO lesson (feeds T-01)
jcmturner/gokrb5/v8 matches keytab entries by KVNO exactly. A keytab
whose KVNO label is stale relative to the KDC fails with a
misleading "AS_REP invalid or client key incorrect" even though the
key material is current. T-01 must: retry once relabelling to the
KDC-issued KVNO, emit a specific error naming the KVNO mismatch, and
cover it in the V-03 failure-mode matrix. Same defect would hit the
D-01 LDAP bind — it is a Kerberos-client issue, not SMB.

## PA-FX-FAST lesson (feeds T-01, D-01, and every later login)
gokrb5 sends PA_REQ_ENC_PA_REP by default. Active Directory does not
answer it, and gokrb5 renders that silence as "KDC did not respond
appropriately to FAST negotiation" — a second misleading first-run
error, in the same family as the KVNO one above: it sends operators
after a FAST or DNS fault that does not exist. The fix is
client.DisablePAFXFAST(true); encrypted-timestamp pre-authentication
is unaffected, only the encrypted-PA-REP negotiation is dropped.
This applies to EVERY gokrb5 login against AD, not just T-01, so
D-01's LDAP bind must pass the same option.

## DC-hardening verification
Library "signing required" readouts are client||server, so they
cannot prove the server. A no-login NEGOTIATE showed the server's
SecurityMode = 0x0003 (signing required); NTLM setup returned
STATUS_NOT_SUPPORTED; the DC set the encryption-required session
flag. The pass is a pass for the right reasons.

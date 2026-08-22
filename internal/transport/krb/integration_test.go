//go:build integration

package krb_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/Omnicef/opengpm/internal/transport/krb"
)

// Nothing about the test domain is committed. Realm, principal, KDC and the
// keytab path all come from the environment, and realm-to-KDC resolution
// comes from the krb5.conf named by KRB5_CONFIG.
const (
	envKeytab    = "OPENGPM_TEST_KEYTAB"
	envPrincipal = "OPENGPM_TEST_PRINCIPAL"
	envRealm     = "OPENGPM_TEST_REALM"
	envKDC       = "OPENGPM_TEST_KDC"
)

type testEnv struct {
	keytab, principal, realm, kdc string
}

// requireEnv skips unless the whole set is present. A half-configured
// environment is an operator mistake, not a reason to run half a test, so
// the skip message names every variable.
func requireEnv(t *testing.T) testEnv {
	t.Helper()
	var missing []string
	get := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			missing = append(missing, k)
		}
		return v
	}
	e := testEnv{
		keytab:    get(envKeytab),
		principal: get(envPrincipal),
		realm:     get(envRealm),
		kdc:       get(envKDC),
	}
	if len(missing) > 0 {
		t.Skipf("no test domain configured; set %s (and KRB5_CONFIG) to run", strings.Join(missing, ", "))
	}
	return e
}

// section returns the part of gokrb5's Client.Print output that follows
// header, up to the next section. Client.sessions is unexported, so this is
// the only window onto whether a TGT was actually obtained.
func section(s, header, next string) string {
	i := strings.Index(s, header)
	if i < 0 {
		return ""
	}
	s = s[i+len(header):]
	if j := strings.Index(s, next); j >= 0 {
		s = s[:j]
	}
	return s
}

func TestFromKeytabHappyPath(t *testing.T) {
	e := requireEnv(t)

	c, err := krb.FromKeytab(e.keytab, e.principal, e.realm)
	if err != nil {
		t.Fatalf("FromKeytab(%s, %s, %s): %v", e.keytab, e.principal, e.realm, err)
	}

	gss := c.GSSAPIClient()
	if gss == nil {
		t.Fatal("GSSAPIClient() = nil, want the client D-01 and T-03 consume")
	}

	// The client is only useful to the LDAP bind and the SMB session if it
	// holds a live TGT, so assert the session exists rather than just that
	// the call returned.
	var buf bytes.Buffer
	gss.Print(&buf)
	sessions := section(buf.String(), "TGT Sessions:", "Service ticket cache:")
	if strings.Contains(sessions, "null") || !strings.Contains(sessions, e.realm) {
		t.Errorf("no TGT session for realm %s after FromKeytab; sessions: %s", e.realm, sessions)
	}

	if err := gss.AffirmLogin(); err != nil {
		t.Errorf("AffirmLogin() = %v, want a usable session", err)
	}

	// KRB5_CONFIG is what pins the realm to a DC (§4.1: LDAP and SMB must
	// hit the same one), so check the configured KDC is the one under test
	// rather than whatever DNS happened to offer.
	n, kdcs, err := gss.Config.GetKDCs(e.realm, true)
	if err != nil {
		t.Fatalf("GetKDCs(%s): %v", e.realm, err)
	}
	if n < 1 {
		t.Fatalf("GetKDCs(%s) resolved no KDCs; check KRB5_CONFIG", e.realm)
	}
	var found bool
	for _, hostPort := range kdcs {
		if h, _, ok := strings.Cut(hostPort, ":"); ok && strings.EqualFold(h, e.kdc) {
			found = true
		}
	}
	if !found {
		t.Errorf("KRB5_CONFIG resolved %v for %s, none of which is %s from %s", kdcs, e.realm, e.kdc, envKDC)
	}
}

// Deliberately not here: the stale-KVNO retry and the clock-skew error.
// Both need a KDC broken on purpose — a keytab relabelled off the KDC's key
// version, and a host clock pushed past the 5 minute tolerance — which is
// V-03's failure-mode matrix (BACKLOG T-01 Oracle), not something a healthy
// test domain can produce. The classification of both is covered without a
// KDC in krb_test.go; V-03 is what proves the real KDC produces the errors
// that classification is fed.

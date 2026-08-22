package transport_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Omnicef/opengpm/internal/transport"
)

// fixture is one recorded SRV answer plus the selection order it must
// produce. See internal/transport/testdata/srv/.
type fixture struct {
	Comment string `json:"comment"`
	Domain  string `json:"domain"`
	Answer  []struct {
		Target   string `json:"target"`
		Port     uint16 `json:"port"`
		Priority uint16 `json:"priority"`
		Weight   uint16 `json:"weight"`
	} `json:"answer"`
	Want    []transport.DC `json:"want"`
	WantErr string         `json:"wantErr"`
}

func (f fixture) srv() []*net.SRV {
	out := make([]*net.SRV, 0, len(f.Answer))
	for _, a := range f.Answer {
		out = append(out, &net.SRV{Target: a.Target, Port: a.Port, Priority: a.Priority, Weight: a.Weight})
	}
	return out
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "srv", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("decoding fixture %s: %v", name, err)
	}
	return f
}

type srvQuery struct{ service, proto, name string }

// fakeResolver answers from a fixture. No test in this package may touch
// the network.
type fakeResolver struct {
	answer []*net.SRV
	err    error
	calls  []srvQuery
}

func (f *fakeResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	f.calls = append(f.calls, srvQuery{service, proto, name})
	if f.err != nil {
		return "", nil, f.err
	}
	return fmt.Sprintf("_%s._%s.%s.", service, proto, name), f.answer, nil
}

func TestSRVParse(t *testing.T) {
	fixtures := []string{
		"multi_priority.json",
		"tied_priority_weights.json",
		"full_tie_hostname.json",
		"single.json",
		"empty.json",
	}

	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			f := loadFixture(t, name)
			r := &fakeResolver{answer: f.srv()}

			got, err := transport.DiscoverDCs(context.Background(), r, f.Domain)

			if f.WantErr == "ErrNoDCs" {
				if !errors.Is(err, transport.ErrNoDCs) {
					t.Fatalf("empty answer: got err %v, want ErrNoDCs", err)
				}
				if len(got) != 0 {
					t.Errorf("empty answer: got %v DCs, want none", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DiscoverDCs: %v", err)
			}
			if !slices.Equal(got, f.Want) {
				t.Errorf("selection order:\n got %+v\nwant %+v", got, f.Want)
			}
		})
	}

	t.Run("QueryName", func(t *testing.T) {
		f := loadFixture(t, "single.json")
		r := &fakeResolver{answer: f.srv()}

		if _, err := transport.DiscoverDCs(context.Background(), r, f.Domain); err != nil {
			t.Fatalf("DiscoverDCs: %v", err)
		}

		want := srvQuery{service: "ldap", proto: "tcp", name: "dc._msdcs." + f.Domain}
		if !slices.Equal(r.calls, []srvQuery{want}) {
			t.Errorf("lookups: got %+v, want exactly one %+v", r.calls, want)
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		// §4.1: LDAP and SMB must pin to the same DC, so the same answer
		// must yield the same order every time. Weight is an ordering
		// key here, never a die roll.
		f := loadFixture(t, "tied_priority_weights.json")

		first, err := transport.DiscoverDCs(context.Background(), &fakeResolver{answer: f.srv()}, f.Domain)
		if err != nil {
			t.Fatalf("DiscoverDCs: %v", err)
		}
		for i := range 50 {
			got, err := transport.DiscoverDCs(context.Background(), &fakeResolver{answer: f.srv()}, f.Domain)
			if err != nil {
				t.Fatalf("call %d: %v", i, err)
			}
			if !slices.Equal(got, first) {
				t.Fatalf("call %d reordered:\n got %+v\nfirst %+v", i, got, first)
			}
		}
	})

	t.Run("TrailingDotStripped", func(t *testing.T) {
		f := loadFixture(t, "multi_priority.json")
		got, err := transport.DiscoverDCs(context.Background(), &fakeResolver{answer: f.srv()}, f.Domain)
		if err != nil {
			t.Fatalf("DiscoverDCs: %v", err)
		}
		for _, dc := range got {
			if dc.Host == "" || dc.Host[len(dc.Host)-1] == '.' {
				t.Errorf("host %q: trailing dot must be stripped", dc.Host)
			}
		}
	})

	t.Run("ResolverErrorWrapped", func(t *testing.T) {
		boom := errors.New("dns: SERVFAIL")
		r := &fakeResolver{err: boom}

		got, err := transport.DiscoverDCs(context.Background(), r, "corp.example.com")

		if !errors.Is(err, boom) {
			t.Fatalf("got err %v, want one wrapping %v", err, boom)
		}
		if err == boom { //nolint:errorlint // asserting the error was wrapped, not returned bare
			t.Error("resolver error returned bare; wrap it with context")
		}
		if errors.Is(err, transport.ErrNoDCs) {
			t.Error("a resolver failure must not be reported as ErrNoDCs")
		}
		if got != nil {
			t.Errorf("got %v DCs alongside an error, want nil", got)
		}
	})
}

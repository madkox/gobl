package migrate

import (
	"sort"
	"strings"
	"testing"
)

// Output of Ruby's Hash#to_yaml as written by rubl.
const rublYAML = `---
1.2.3.4:
  :counter: 3
  :permaban: true
  :timestamp: 1700000000
5.6.7.8:
  :counter: 1
  :permaban: false
  :timestamp: 1700000100
9.9.9.9:
  :counter: 0
  :permaban: false
  :timestamp: 1700000200
2001:db8::1:
  :counter: 1
  :permaban: true
  :timestamp: 1700000300
not-an-ip:
  :counter: 1
`

func TestParseRublYAML(t *testing.T) {
	hosts, warns, err := ParseRublYAML(strings.NewReader(rublYAML), 1800000000)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 {
		t.Fatalf("warnings = %v", warns)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP.Less(hosts[j].IP) })
	if len(hosts) != 3 {
		t.Fatalf("hosts = %+v", hosts)
	}
	h := hosts[0]
	if h.IP.String() != "1.2.3.4" || h.Counter != 3 || !h.Perm || h.LastSeen != 1700000000 || h.PermSince != 1700000000 {
		t.Fatalf("1.2.3.4 = %+v", h)
	}
	if h := hosts[1]; h.IP.String() != "5.6.7.8" || h.Perm || h.Counter != 1 {
		t.Fatalf("5.6.7.8 = %+v", h)
	}
	if h := hosts[2]; h.Family != 6 || !h.Perm {
		t.Fatalf("v6 = %+v", h)
	}
}

func TestParseEmpty(t *testing.T) {
	hosts, _, err := ParseRublYAML(strings.NewReader(""), 1)
	if err != nil || len(hosts) != 0 {
		t.Fatal(hosts, err)
	}
}

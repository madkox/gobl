package ipaddr

import "testing"

func TestParse(t *testing.T) {
	ok := map[string]string{
		"1.2.3.4":          "1.2.3.4",
		"::ffff:1.2.3.4":   "1.2.3.4",
		"2001:db8::1":      "2001:db8::1",
		"2001:DB8:0:0::01": "2001:db8::1",
	}
	for in, want := range ok {
		a, err := Parse(in)
		if err != nil || a.String() != want {
			t.Errorf("Parse(%q) = %v, %v; want %s", in, a, err, want)
		}
	}
	for _, in := range []string{"", "1.2.3", "1.2.3.4/32", "fe80::1%eth0", "0.0.0.0", "::", "1.2.3.4; rm -rf /"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q): expected error", in)
		}
	}
}

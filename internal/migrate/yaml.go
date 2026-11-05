// Package migrate imports the list.yml of rubl (gobl's Ruby predecessor)
// into the gobl store.
package migrate

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/madkox/gobl/internal/ipaddr"
	"github.com/madkox/gobl/internal/policy"
	"github.com/madkox/gobl/internal/store"
)

// ParseRublYAML reads rubl's list.yml. Ruby writes Symbol keys as
// ":counter", ":permaban", ":timestamp"; plain keys are accepted too.
// Records that rubl would delete on its next maintain (non-perm with
// counter < 1) are dropped. Invalid addresses are reported as warnings.
func ParseRublYAML(r io.Reader, now int64) (hosts []store.Host, warnings []string, err error) {
	var raw map[string]map[string]any
	if err := yaml.NewDecoder(r).Decode(&raw); err != nil {
		if err == io.EOF {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("parse yaml: %w", err)
	}
	for key, fields := range raw {
		ip, err := ipaddr.Parse(key)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		var counter, ts int64
		var perm bool
		for k, v := range fields {
			switch strings.TrimPrefix(k, ":") {
			case "counter":
				counter = toInt(v)
			case "timestamp":
				ts = toInt(v)
			case "permaban":
				perm, _ = v.(bool)
			}
		}
		if !perm && counter < 1 {
			continue
		}
		if ts <= 0 {
			ts = now
		}
		rec := policy.Record{Counter: counter, FirstSeen: ts, LastSeen: ts, DecayAnchor: ts, Perm: perm}
		if perm {
			rec.PermSince = ts
		}
		hosts = append(hosts, store.Host{IP: ip, Family: ipaddr.Family(ip), Record: rec, Source: "local", UpdatedAt: now})
	}
	return hosts, warnings, nil
}

func toInt(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case uint64:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}

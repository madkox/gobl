package nft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// execBackend runs the nft binary. Arguments are passed directly, never
// through a shell, and addresses are validated before they get here.
type execBackend struct {
	family, table string
	bin           string
}

func newExec(family, table string) *execBackend {
	return &execBackend{family: family, table: table, bin: "nft"}
}

func (b *execBackend) Close() error { return nil }

func (b *execBackend) run(args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(b.bin, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (b *execBackend) EnsureSet(name string, v6 bool) error {
	typ := "ipv4_addr"
	if v6 {
		typ = "ipv6_addr"
	}
	// "add set" is a no-op if the set exists with the same type.
	_, err := b.run("add", "set", b.family, b.table, name, "{", "type", typ, ";", "}")
	return err
}

func joinIPs(ips []netip.Addr) string {
	s := make([]string, len(ips))
	for i, ip := range ips {
		s[i] = ip.String()
	}
	return strings.Join(s, ", ")
}

func (b *execBackend) Add(set string, ips []netip.Addr) error {
	for start := 0; start < len(ips); start += batchSize {
		chunk := ips[start:min(start+batchSize, len(ips))]
		if _, err := b.run("add", "element", b.family, b.table, set, "{", joinIPs(chunk), "}"); err != nil {
			return err
		}
	}
	return nil
}

func (b *execBackend) Delete(set string, ips []netip.Addr) error {
	if len(ips) == 0 {
		return nil
	}
	have, err := b.List(set)
	if err != nil {
		return err
	}
	ips = Present(ips, have)
	for start := 0; start < len(ips); start += batchSize {
		chunk := ips[start:min(start+batchSize, len(ips))]
		if _, err := b.run("delete", "element", b.family, b.table, set, "{", joinIPs(chunk), "}"); err != nil {
			return err
		}
	}
	return nil
}

func (b *execBackend) Flush(set string) error {
	_, err := b.run("flush", "set", b.family, b.table, set)
	return err
}

func (b *execBackend) List(set string) ([]netip.Addr, error) {
	out, err := b.run("-j", "list", "set", b.family, b.table, set)
	if err != nil {
		return nil, err
	}
	return parseSetJSON(out)
}

// parseSetJSON extracts addresses from `nft -j list set` output. Elements
// are plain strings, or objects {"elem": {"val": ...}} when they carry
// timeouts or comments.
func parseSetJSON(data []byte) ([]netip.Addr, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}
	var out []netip.Addr
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			var s string
			if json.Unmarshal(raw, &s) != nil {
				var obj struct {
					Elem struct {
						Val string `json:"val"`
					} `json:"elem"`
				}
				if json.Unmarshal(raw, &obj) != nil {
					continue
				}
				s = obj.Elem.Val
			}
			if a, err := netip.ParseAddr(s); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out, nil
}

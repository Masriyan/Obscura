package modules

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// faviconPivotModule ports modules/favicon_pivot.py (name "favicon_pivot"):
// computes the favicon's Shodan-style MurmurHash3 and pivots through Shodan to
// find hosts sharing the same favicon. Key-gated on SHODAN_API_KEY.
type faviconPivotModule struct{}

func init() { engine.Register(faviconPivotModule{}) }

func (faviconPivotModule) Name() string { return "favicon_pivot" }
func (faviconPivotModule) Description() string {
	return "Computes favicon hash and pivots through Shodan to find all servers sharing the same favicon."
}
func (faviconPivotModule) Category() string       { return "intel" }
func (faviconPivotModule) Dependencies() []string { return nil }
func (faviconPivotModule) RequiredKey() string    { return "SHODAN_API_KEY" }
func (faviconPivotModule) RateLimitRPM() int      { return 0 }

func (faviconPivotModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, cfg *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	base := strings.TrimRight(target.URL, "/")
	var data []byte
	var favURL string
	for _, p := range []string{"/favicon.ico", "/favicon.png", "/apple-touch-icon.png"} {
		resp, err := client.Get(ctx, base+p)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1_000_000))
			resp.Body.Close()
			if len(b) > 0 {
				data, favURL = b, base+p
				break
			}
			continue
		}
		resp.Body.Close()
	}
	if data == nil {
		return map[string]any{"favicon_found": false, "message": "No favicon found"}, nil
	}

	sum := md5.Sum(data)
	hash := faviconMMH3(data)
	res := map[string]any{
		"favicon_found": true,
		"favicon_url":   favURL,
		"size_bytes":    len(data),
		"md5":           hex.EncodeToString(sum[:]),
		"mmh3_hash":     hash,
		"shodan_query":  fmt.Sprintf("http.favicon.hash:%d", hash),
		"related_hosts": []any{},
		"total_matches": 0,
	}

	hosts := shodanFaviconSearch(ctx, client, cfg.ShodanKey, hash)
	if len(hosts) > 50 {
		hosts = hosts[:50]
	}
	res["related_hosts"] = hosts
	res["total_matches"] = len(hosts)
	if len(hosts) > 1 {
		res["risk_assessment"] = fmt.Sprintf("Found %d other hosts with identical favicon — possible shared infrastructure, staging, or related orgs.", len(hosts))
	} else {
		res["risk_assessment"] = "Favicon appears unique — no related hosts found via Shodan."
	}
	return res, nil
}

// faviconMMH3 replicates Shodan's favicon hash: mmh3.hash(base64.encodebytes(data)).
// Python's base64.encodebytes wraps at 76 chars and appends a trailing newline.
func faviconMMH3(data []byte) int32 {
	b64 := base64EncodeWrapped(data)
	return murmur3Hash32([]byte(b64), 0)
}

func base64EncodeWrapped(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		sb.WriteString(enc[i:end])
		sb.WriteByte('\n')
	}
	return sb.String()
}

// murmur3Hash32 is the 32-bit MurmurHash3, returning a signed int32 like mmh3.hash.
func murmur3Hash32(key []byte, seed uint32) int32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	length := len(key)
	nblocks := length / 4
	h1 := seed
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(key[i*4:])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	tail := key[nblocks*4:]
	var k1 uint32
	switch len(tail) & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1)
}

func shodanFaviconSearch(ctx context.Context, client *httpx.Client, key string, hash int32) []any {
	if key == "" {
		return nil
	}
	url := "https://api.shodan.io/shodan/host/search?key=" + key + "&query=" + "http.favicon.hash:" + strconv.Itoa(int(hash))
	resp, err := client.Get(ctx, url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	var parsed struct {
		Matches []struct {
			IPStr     string   `json:"ip_str"`
			Port      int      `json:"port"`
			Org       string   `json:"org"`
			Hostnames []string `json:"hostnames"`
			OS        string   `json:"os"`
			Product   string   `json:"product"`
			Location  struct {
				CountryName string `json:"country_name"`
			} `json:"location"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	out := make([]any, 0, len(parsed.Matches))
	for _, m := range parsed.Matches {
		out = append(out, map[string]any{
			"ip": m.IPStr, "port": m.Port, "org": m.Org, "hostnames": m.Hostnames,
			"location": m.Location.CountryName, "os": m.OS, "product": m.Product,
		})
	}
	return out
}

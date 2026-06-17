package server

import "fmt"

// graphNode / graphEdge model the attack-surface relationship graph.
type graphNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"` // target | subdomain | ip | asn | issuer
}

type graphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type graphData struct {
	Nodes []graphNode `json:"nodes"`
	Edges []graphEdge `json:"edges"`
}

// buildGraph derives a target→subdomain→ip→asn (+cert issuers) graph from a
// scan's results map. It is resilient to missing modules.
func buildGraph(results map[string]any) graphData {
	g := graphData{}
	seen := map[string]bool{}
	add := func(id, label, typ string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		g.Nodes = append(g.Nodes, graphNode{ID: id, Label: label, Type: typ})
	}
	edge := func(a, b string) {
		if a != "" && b != "" {
			g.Edges = append(g.Edges, graphEdge{Source: a, Target: b})
		}
	}

	meta, _ := results["_meta"].(map[string]any)
	target, _ := meta["host"].(string)
	if target == "" {
		target, _ = meta["target"].(string)
	}
	if target == "" {
		target = "target"
	}
	add(target, target, "target")

	// DNS A records -> target IPs.
	if dns, ok := results["dns_records"].(map[string]any); ok {
		for _, ip := range toStrings(dns["A"]) {
			add("ip:"+ip, ip, "ip")
			edge(target, "ip:"+ip)
		}
	}

	// Subdomains -> their IPs.
	if ss, ok := results["subdomain_scan"].(map[string]any); ok {
		if found, ok := ss["found"].([]any); ok {
			for _, f := range found {
				m, ok := f.(map[string]any)
				if !ok {
					continue
				}
				sub, _ := m["subdomain"].(string)
				if sub == "" || sub == target {
					continue
				}
				add("sub:"+sub, sub, "subdomain")
				edge(target, "sub:"+sub)
				for _, ip := range toStrings(m["ips"]) {
					add("ip:"+ip, ip, "ip")
					edge("sub:"+sub, "ip:"+ip)
				}
			}
		}
	}

	// IP geolocation -> ASN/org for the primary IP.
	if geo, ok := results["ip_geolocation"].(map[string]any); ok {
		if sum, ok := geo["summary"].(map[string]any); ok {
			asn, _ := sum["asn"].(string)
			pip, _ := sum["primary_ip"].(string)
			if asn != "" {
				add("asn:"+asn, asn, "asn")
				if pip != "" {
					add("ip:"+pip, pip, "ip")
					edge("ip:"+pip, "asn:"+asn)
				} else {
					edge(target, "asn:"+asn)
				}
			}
		}
	}

	// Certificate issuers from CT logs.
	if ct, ok := results["cert_transparency"].(map[string]any); ok {
		if an, ok := ct["analysis"].(map[string]any); ok {
			for _, iss := range toStrings(an["unique_issuers"]) {
				id := "issuer:" + iss
				label := iss
				if len(label) > 40 {
					label = label[:40] + "…"
				}
				add(id, label, "issuer")
				edge(target, id)
			}
		}
	}

	return g
}

func toStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		switch s := e.(type) {
		case string:
			out = append(out, s)
		default:
			out = append(out, fmt.Sprint(s))
		}
	}
	return out
}

package export

import (
	"strings"
	"testing"
	"time"
)

func sampleScan() Scan {
	return Scan{
		ID: 7, Target: "example.com", ScanDate: time.Unix(1700000000, 0).UTC(),
		Results: map[string]any{
			"_meta": map[string]any{"target": "example.com"},
			"http_probe": map[string]any{
				"overall_severity": "critical",
				"risk_assessment":  "critical exposure",
				"findings": []any{
					map[string]any{"name": "Git Repository", "severity": "critical", "description": "exposed .git", "url": "https://example.com/.git/HEAD"},
				},
			},
			"ssl_chain": map[string]any{
				"issues": []any{
					map[string]any{"issue": "Self-signed", "severity": "medium", "detail": "missing intermediates"},
				},
			},
		},
	}
}

func TestExtractFindings(t *testing.T) {
	f := ExtractFindings(sampleScan().Results)
	if len(f) < 2 {
		t.Fatalf("expected >=2 findings, got %d", len(f))
	}
	var sawCritical bool
	for _, x := range f {
		if x.Severity == "critical" && strings.Contains(x.Title, "Git") {
			sawCritical = true
		}
	}
	if !sawCritical {
		t.Fatal("expected the critical Git finding to be extracted")
	}
}

func TestCSVHeaderAndRows(t *testing.T) {
	out := string(CSV(sampleScan()))
	if !strings.HasPrefix(out, "scan_id,target,scan_date,module,severity,title,description,url") {
		t.Fatalf("CSV header wrong: %q", strings.SplitN(out, "\n", 2)[0])
	}
	if !strings.Contains(out, "Git Repository") {
		t.Fatal("CSV missing finding row")
	}
}

func TestSTIXValidBundle(t *testing.T) {
	out := string(STIX(sampleScan()))
	if !strings.Contains(out, `"type": "bundle"`) || !strings.Contains(out, `"spec_version": "2.1"`) {
		t.Fatal("STIX output is not a 2.1 bundle")
	}
	if !strings.Contains(out, `"type": "indicator"`) {
		t.Fatal("STIX bundle missing indicators")
	}
}

func TestLEEFAndECS(t *testing.T) {
	if !strings.HasPrefix(string(QRadarLEEF(sampleScan())), "LEEF:2.0|Obscura Scan|") {
		t.Fatal("QRadar LEEF header malformed")
	}
	if !strings.Contains(string(ElasticECS(sampleScan())), `"ecs"`) {
		t.Fatal("Elastic ECS missing ecs field")
	}
	if !strings.Contains(string(SplunkCIM(sampleScan())), `"vendor":"Obscura Scan"`) {
		t.Fatal("Splunk CIM missing vendor")
	}
}

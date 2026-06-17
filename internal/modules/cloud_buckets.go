package modules

import (
	"context"
	"io"
	"strings"
	"sync"

	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/httpx"
	"obscurascan/internal/safety"
)

// cloudBucketsModule permutes likely cloud storage bucket names from the target
// and probes S3/GCS/Azure over HTTP (name "cloud_buckets") — keyless, no cloud
// credentials. Flags existing and (worse) publicly-listable buckets.
type cloudBucketsModule struct{}

func init() { engine.Register(cloudBucketsModule{}) }

func (cloudBucketsModule) Name() string { return "cloud_buckets" }
func (cloudBucketsModule) Description() string {
	return "Hunts for the target's S3/GCS/Azure storage buckets by name permutation; flags open/listable ones."
}
func (cloudBucketsModule) Category() string       { return "semi-offensive" }
func (cloudBucketsModule) Dependencies() []string { return nil }
func (cloudBucketsModule) RequiredKey() string    { return "" }
func (cloudBucketsModule) RateLimitRPM() int      { return 60 }

var bucketAffixes = []string{
	"", "-prod", "-dev", "-staging", "-stage", "-test", "-backup", "-backups", "-assets",
	"-static", "-media", "-uploads", "-files", "-data", "-public", "-private", "-internal",
	"-logs", "-cdn", "-images", "-www", "-web", "-app", "-storage", "-archive",
}

// bucketProviders map a bucket name to a probe URL + provider label.
func bucketProviders(name string) []struct{ provider, url string } {
	return []struct{ provider, url string }{
		{"AWS S3", "https://" + name + ".s3.amazonaws.com/"},
		{"Google Cloud Storage", "https://storage.googleapis.com/" + name + "/"},
		{"Azure Blob", "https://" + name + ".blob.core.windows.net/?comp=list"},
	}
}

func (cloudBucketsModule) Run(ctx context.Context, target safety.Target, _ *engine.SharedState, _ *config.ObscuraConfig, client *httpx.Client) (map[string]any, error) {
	// Build candidate bucket base names from the domain.
	host := target.Host
	label := host
	if i := strings.IndexByte(host, '.'); i > 0 {
		label = host[:i]
	}
	bases := map[string]bool{label: true, strings.ReplaceAll(host, ".", "-"): true, strings.ReplaceAll(host, ".", ""): true}

	var names []string
	for b := range bases {
		for _, a := range bucketAffixes {
			names = append(names, b+a)
		}
	}

	type hit struct {
		Bucket, Provider, URL, State string
	}
	var (
		mu       sync.Mutex
		hits     []hit
		wg       sync.WaitGroup
		sem      = make(chan struct{}, 15)
		tested   int
		findings []map[string]any
	)
	for _, name := range names {
		for _, p := range bucketProviders(name) {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			tested++
			go func(bucket, provider, url string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				state := probeBucket(ctx, client, url)
				if state == "" {
					return
				}
				mu.Lock()
				hits = append(hits, hit{bucket, provider, url, state})
				if state == "open/listable" {
					findings = append(findings, map[string]any{
						"name": "Public bucket listing: " + bucket, "severity": "high",
						"description": provider + " bucket is publicly listable — data exposure.", "url": url,
					})
				} else {
					findings = append(findings, map[string]any{
						"name": "Bucket exists: " + bucket, "severity": "low",
						"description": provider + " bucket exists (access controlled).", "url": url,
					})
				}
				mu.Unlock()
			}(name, p.provider, p.url)
		}
	}
	wg.Wait()

	rows := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		rows = append(rows, map[string]any{"bucket": h.Bucket, "provider": h.Provider, "url": h.URL, "state": h.State})
	}
	overall := "info"
	for _, f := range findings {
		if f["severity"] == "high" {
			overall = "high"
		} else if overall == "info" {
			overall = "low"
		}
	}
	return map[string]any{
		"candidates_tested": tested,
		"buckets":           rows,
		"buckets_found":     len(rows),
		"findings":          findings,
		"overall_severity":  overall,
	}, nil
}

// probeBucket returns "" (not found), "exists" (403/AccessDenied), or
// "open/listable" (200 with a listing body).
func probeBucket(ctx context.Context, client *httpx.Client, url string) string {
	resp, err := client.Get(ctx, url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	text := string(body)
	switch resp.StatusCode {
	case 200:
		if strings.Contains(text, "<ListBucketResult") || strings.Contains(text, "<EnumerationResults") || strings.Contains(text, "<Contents>") {
			return "open/listable"
		}
		return "exists"
	case 403:
		if strings.Contains(text, "AccessDenied") || strings.Contains(text, " AuthenticationRequired") || strings.Contains(text, "PublicAccessNotPermitted") {
			return "exists"
		}
		return "exists"
	default:
		return ""
	}
}

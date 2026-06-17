package ml

import (
	"math/rand"
	"testing"
)

func TestRiskScoreBands(t *testing.T) {
	cases := []struct {
		c     SeverityCounts
		level string
	}{
		{SeverityCounts{}, "info"},
		{SeverityCounts{Low: 1}, "low"},
		{SeverityCounts{Medium: 4}, "medium"},
		{SeverityCounts{High: 3}, "high"},
		{SeverityCounts{Critical: 1}, "critical"},
	}
	for _, tc := range cases {
		if _, lvl := RiskScore(tc.c); lvl != tc.level {
			t.Errorf("RiskScore(%+v) level = %s, want %s", tc.c, lvl, tc.level)
		}
	}
	// A single critical must never read below the critical band.
	if s, _ := RiskScore(SeverityCounts{Critical: 1}); s < 75 {
		t.Fatalf("one critical scored %d, want >=75", s)
	}
	// Score is capped at 100.
	if s, _ := RiskScore(SeverityCounts{Critical: 10}); s != 100 {
		t.Fatalf("many criticals scored %d, want capped 100", s)
	}
}

func TestIsolationForestFlagsOutlier(t *testing.T) {
	// Dense cluster around the origin + one far outlier.
	rng := rand.New(rand.NewSource(1))
	var data [][]float64
	for i := 0; i < 200; i++ {
		data = append(data, []float64{rng.NormFloat64(), rng.NormFloat64()})
	}
	outlier := []float64{12, 12}
	normal := []float64{0, 0}

	f := Fit(data, Options{NumTrees: 100, SampleSize: 128, Seed: 42})
	so := f.Score(outlier)
	sn := f.Score(normal)
	if so <= sn {
		t.Fatalf("outlier score %.3f should exceed normal score %.3f", so, sn)
	}
	if so < 0.6 {
		t.Fatalf("outlier score %.3f should be clearly anomalous (>0.6)", so)
	}
}

func TestStandardize(t *testing.T) {
	data := [][]float64{{1, 10}, {2, 20}, {3, 30}}
	out := Standardize(data)
	// Column means should be ~0 after scaling.
	var sum0 float64
	for _, r := range out {
		sum0 += r[0]
	}
	if sum0 > 1e-9 || sum0 < -1e-9 {
		t.Fatalf("standardized column mean = %v, want ~0", sum0)
	}
}

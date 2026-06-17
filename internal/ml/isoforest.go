// Package ml provides the small amount of machine-learning Obscura Scan needs:
// an IsolationForest for anomaly scoring (the only real ML dependency in the
// Python AEGIS, used by domain_risk_scoring) and a transparent weighted risk
// scorer. The IsolationForest is a faithful, self-contained port of the
// algorithm (no heavyweight framework), scoring by average path length.
package ml

import (
	"math"
	"math/rand"
)

// IsolationForest is an ensemble of random isolation trees over feature vectors.
type IsolationForest struct {
	trees       []*isoNode
	sampleSize  int
	avgPathNorm float64 // c(n): expected path length normalizer
}

type isoNode struct {
	left, right *isoNode
	feature     int
	split       float64
	size        int // samples reaching this (external) node
	external    bool
}

// Options configures the forest.
type Options struct {
	NumTrees   int
	SampleSize int
	Seed       int64
}

// Fit builds the forest from data ([]sample][]feature).
func Fit(data [][]float64, opts Options) *IsolationForest {
	if opts.NumTrees <= 0 {
		opts.NumTrees = 100
	}
	if opts.SampleSize <= 0 || opts.SampleSize > len(data) {
		opts.SampleSize = min(256, len(data))
	}
	rng := rand.New(rand.NewSource(opts.Seed))
	heightLimit := int(math.Ceil(math.Log2(float64(max(opts.SampleSize, 2)))))

	f := &IsolationForest{
		sampleSize:  opts.SampleSize,
		avgPathNorm: cFactor(opts.SampleSize),
	}
	if len(data) == 0 || len(data[0]) == 0 {
		return f
	}
	dim := len(data[0])
	for t := 0; t < opts.NumTrees; t++ {
		sample := subsample(data, opts.SampleSize, rng)
		f.trees = append(f.trees, buildTree(sample, 0, heightLimit, dim, rng))
	}
	return f
}

func buildTree(data [][]float64, depth, limit, dim int, rng *rand.Rand) *isoNode {
	if depth >= limit || len(data) <= 1 {
		return &isoNode{external: true, size: len(data)}
	}
	feature := rng.Intn(dim)
	min, max := data[0][feature], data[0][feature]
	for _, row := range data {
		if row[feature] < min {
			min = row[feature]
		}
		if row[feature] > max {
			max = row[feature]
		}
	}
	if min == max {
		return &isoNode{external: true, size: len(data)}
	}
	split := min + rng.Float64()*(max-min)
	var left, right [][]float64
	for _, row := range data {
		if row[feature] < split {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}
	return &isoNode{
		feature: feature, split: split,
		left:  buildTree(left, depth+1, limit, dim, rng),
		right: buildTree(right, depth+1, limit, dim, rng),
	}
}

// Score returns the anomaly score in [0,1] for one sample; higher = more
// anomalous. ~0.5 is the population norm; >0.6-0.7 indicates an outlier.
func (f *IsolationForest) Score(x []float64) float64 {
	if len(f.trees) == 0 || f.avgPathNorm == 0 {
		return 0
	}
	var total float64
	for _, t := range f.trees {
		total += pathLength(t, x, 0)
	}
	avg := total / float64(len(f.trees))
	return math.Pow(2, -avg/f.avgPathNorm)
}

func pathLength(n *isoNode, x []float64, depth int) float64 {
	if n.external {
		return float64(depth) + cFactor(n.size)
	}
	if x[n.feature] < n.split {
		return pathLength(n.left, x, depth+1)
	}
	return pathLength(n.right, x, depth+1)
}

// cFactor is c(n): the average path length of an unsuccessful BST search,
// used to normalize scores.
func cFactor(n int) float64 {
	if n <= 1 {
		return 0
	}
	h := math.Log(float64(n-1)) + 0.5772156649 // harmonic approx + Euler-Mascheroni
	return 2*h - (2*float64(n-1))/float64(n)
}

func subsample(data [][]float64, k int, rng *rand.Rand) [][]float64 {
	if k >= len(data) {
		return data
	}
	idx := rng.Perm(len(data))[:k]
	out := make([][]float64, k)
	for i, j := range idx {
		out[i] = data[j]
	}
	return out
}

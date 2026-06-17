package ml

import "math"

// SeverityCounts holds how many findings of each severity a scan produced.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// severity weights (per-finding contribution toward the 0-100 risk score).
const (
	wCritical = 40
	wHigh     = 20
	wMedium   = 8
	wLow      = 3
)

// RiskScore converts severity counts into a 0-100 score and a level label.
// It is a transparent weighted heuristic (the documented §10 alternative to a
// black-box model): each finding adds its severity weight, capped at 100, with
// any critical present flooring the result into the "critical" band.
func RiskScore(c SeverityCounts) (int, string) {
	score := c.Critical*wCritical + c.High*wHigh + c.Medium*wMedium + c.Low*wLow
	if score > 100 {
		score = 100
	}
	// A single critical finding should never read as "low".
	if c.Critical > 0 && score < 75 {
		score = 75
	}
	return score, RiskLevel(score)
}

// RiskLevel maps a 0-100 score to a band.
func RiskLevel(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

// Standardize z-scores a feature matrix column-wise (StandardScaler), returning
// the scaled matrix. Constant columns are left at zero. Used to prepare feature
// vectors for the IsolationForest.
func Standardize(data [][]float64) [][]float64 {
	if len(data) == 0 {
		return data
	}
	dim := len(data[0])
	mean := make([]float64, dim)
	std := make([]float64, dim)
	for _, row := range data {
		for j := 0; j < dim && j < len(row); j++ {
			mean[j] += row[j]
		}
	}
	n := float64(len(data))
	for j := range mean {
		mean[j] /= n
	}
	for _, row := range data {
		for j := 0; j < dim && j < len(row); j++ {
			d := row[j] - mean[j]
			std[j] += d * d
		}
	}
	for j := range std {
		std[j] = math.Sqrt(std[j] / n)
	}
	out := make([][]float64, len(data))
	for i, row := range data {
		scaled := make([]float64, dim)
		for j := 0; j < dim && j < len(row); j++ {
			if std[j] > 0 {
				scaled[j] = (row[j] - mean[j]) / std[j]
			}
		}
		out[i] = scaled
	}
	return out
}

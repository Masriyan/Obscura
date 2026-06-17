package export

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// DOCX renders a minimal, valid Office Open XML (.docx) report by hand — a zip
// of the three required parts. No third-party OOXML library is needed.
func DOCX(sc Scan) []byte {
	risk, level := scanRiskLevel(sc.Results)
	findings := ExtractFindings(sc.Results)
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(findings, func(i, j int) bool { return rank[findings[i].Severity] < rank[findings[j].Severity] })

	var body strings.Builder
	body.WriteString(para("Obscura Scan — Security Report", runProps{bold: true, sizeHalfPt: 36, color: "1F2430"}))
	body.WriteString(para(sc.Target, runProps{bold: true, sizeHalfPt: 28}))
	body.WriteString(para(fmt.Sprintf("Scan #%d  ·  %s", sc.ID, sc.ScanDate.Format("2006-01-02 15:04 MST")), runProps{sizeHalfPt: 18, color: "6E6E78"}))
	body.WriteString(para(fmt.Sprintf("Risk score: %d / 100  (%s)", risk, strings.Title(level)), runProps{bold: true, sizeHalfPt: 24, color: sevHex(level)}))

	counts := countBy(findings)
	body.WriteString(para(fmt.Sprintf("Critical %d   High %d   Medium %d   Low %d   ·   %d findings total",
		counts["critical"], counts["high"], counts["medium"], counts["low"], len(findings)), runProps{sizeHalfPt: 18, color: "6E6E78"}))

	body.WriteString(para("Findings", runProps{bold: true, sizeHalfPt: 26}))
	if len(findings) == 0 {
		body.WriteString(para("No findings of note for the modules run.", runProps{italic: true, color: "6E6E78"}))
	}
	for _, f := range findings {
		title := fmt.Sprintf("[%s] %s", strings.ToUpper(f.Severity), f.Title)
		body.WriteString(para(title, runProps{bold: true, sizeHalfPt: 20, color: sevHex(f.Severity)}))
		detail := f.Module
		if f.Description != "" {
			detail += " — " + f.Description
		}
		body.WriteString(para(detail, runProps{sizeHalfPt: 18, color: "44444C"}))
	}

	if meta, ok := sc.Results["_meta"].(map[string]any); ok {
		if ms, ok := meta["module_status"].(map[string]any); ok && len(ms) > 0 {
			body.WriteString(para("Module Coverage", runProps{bold: true, sizeHalfPt: 26}))
			names := make([]string, 0, len(ms))
			for k := range ms {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, n := range names {
				st, _ := ms[n].(string)
				body.WriteString(para(n+" — "+st, runProps{sizeHalfPt: 18}))
			}
		}
	}

	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		body.String() +
		`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/></w:sectPr></w:body></w:document>`

	return zipDocx(document)
}

type runProps struct {
	bold, italic bool
	sizeHalfPt   int
	color        string
}

// para builds a <w:p> with one styled run.
func para(text string, rp runProps) string {
	var rpr strings.Builder
	rpr.WriteString("<w:rPr>")
	if rp.bold {
		rpr.WriteString("<w:b/>")
	}
	if rp.italic {
		rpr.WriteString("<w:i/>")
	}
	if rp.color != "" {
		fmt.Fprintf(&rpr, `<w:color w:val="%s"/>`, rp.color)
	}
	if rp.sizeHalfPt > 0 {
		fmt.Fprintf(&rpr, `<w:sz w:val="%d"/>`, rp.sizeHalfPt)
	}
	rpr.WriteString("</w:rPr>")
	return fmt.Sprintf(`<w:p><w:pPr><w:spacing w:after="80"/></w:pPr><w:r>%s<w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		rpr.String(), xmlEscape(text))
}

func sevHex(sev string) string {
	switch sev {
	case "critical":
		return "E5484D"
	case "high":
		return "EF7234"
	case "medium":
		return "D8A01E"
	case "low":
		return "4C82F7"
	default:
		return "8B8D98"
	}
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// zipDocx assembles the three mandatory OOXML parts into a .docx zip.
func zipDocx(documentXML string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, content string) {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
	}
	add("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`)
	add("_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`)
	add("word/document.xml", documentXML)
	_ = zw.Close()
	return buf.Bytes()
}

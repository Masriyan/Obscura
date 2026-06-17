// Package server is the Obscura Scan HTTP layer: a chi router serving the
// embedded UI (html/template), the SSE progress stream, a small JSON API, and
// the scan-launch flow wired to the engine. Templates and static assets are
// embedded (§17) so the binary runs standalone from any directory.
package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"obscurascan/internal/ai"
	"obscurascan/internal/config"
	"obscurascan/internal/engine"
	"obscurascan/internal/export"
	"obscurascan/internal/httpx"
	"obscurascan/internal/metrics"
	"obscurascan/internal/safety"
	"obscurascan/internal/store"
	"obscurascan/web"
)

//go:embed templates/*.html
var templateFS embed.FS

// Server holds the HTTP dependencies.
type Server struct {
	cfg       *config.ObscuraConfig
	store     *store.Store
	runner    *engine.Runner
	client    *httpx.Client
	ai        *ai.Engine
	limiter   *ipLimiter
	templates map[string]*template.Template
	rootCtx   context.Context
}

// New builds a Server and parses the embedded templates. The Runner is shared
// (the scheduler uses the same instance).
func New(ctx context.Context, cfg *config.ObscuraConfig, st *store.Store, client *httpx.Client, runner *engine.Runner) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		store:   st,
		runner:  runner,
		client:  client,
		ai:      ai.New(cfg, client),
		limiter: newIPLimiter(cfg.APIRateLimit),
		rootCtx: ctx,
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) parseTemplates() error {
	pages := []string{"index", "results", "scans", "modules", "progress", "scheduled", "settings", "compare", "graph", "campaigns", "campaign"}
	s.templates = make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		t := template.New(p).Funcs(funcMap())
		if _, err := t.ParseFS(templateFS, "templates/base.html", "templates/"+p+".html"); err != nil {
			return fmt.Errorf("parse template %s: %w", p, err)
		}
		s.templates[p] = t
	}
	return nil
}

// Handler builds the chi router with all routes and middleware.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger)
	r.Use(csrfMiddleware)

	// Embedded static assets.
	staticSub, _ := fs.Sub(web.Static, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// UI pages.
	r.Get("/", s.handleIndex)
	r.Post("/scan", s.handleScan)
	r.Get("/scans", s.handleScans)
	r.Get("/modules", s.handleModules)
	r.Get("/view/{id}", s.handleView)
	r.Get("/view/by-task/{taskID}", s.handleViewByTask)
	r.Get("/stream/{taskID}", s.handleStream)
	r.Get("/scheduled", s.handleScheduled)
	r.Post("/scheduled", s.handleScheduleCreate)
	r.Post("/scheduled/delete/{id}", s.handleScheduleDelete)
	r.Get("/settings", s.handleSettings)
	r.Get("/graph/{id}", s.handleGraph)
	r.Get("/compare/{a}/{b}", s.handleCompare)
	r.Get("/campaigns", s.handleCampaigns)
	r.Post("/campaigns", s.handleCampaignCreate)
	r.Get("/campaign/{id}", s.handleCampaignView)
	r.Post("/scan/{id}/notes", s.handleAddNote)
	r.Post("/notes/delete/{id}", s.handleDeleteNote)

	// Health + metrics + browser exports (cookie/CSRF world, not token-auth'd).
	r.Get("/healthz", s.handleHealth)
	r.Get("/metrics", metrics.Handler())
	r.Get("/export/json/{id}", s.handleExportJSON)
	r.Get("/export/{format}/{id}", s.handleExport)

	// REST API v1 — guarded by per-IP rate limit + optional Bearer auth + audit.
	r.Group(func(api chi.Router) {
		api.Use(s.apiMiddleware)
		api.Get("/api/v1/tasks/{taskID}", s.handleAPITask)
		api.Get("/api/v1/ai/status", s.handleAIStatus)
		api.Post("/api/v1/ai/chat", s.handleAIChat)
		api.Get("/api/v1/ai/analyze/{id}", s.handleAIAnalyze)
	})

	return r
}

// ---- helpers ----

func (s *Server) render(w http.ResponseWriter, page string, data map[string]any) {
	t, ok := s.templates[page]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["Version"] = s.cfg.Version
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		slog.Error("template render failed", "page", page, "err", err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- handlers ----

type moduleView struct {
	Name, Description, Category, RequiredKey string
}

func registeredModules() []moduleView {
	mods := engine.All()
	out := make([]moduleView, 0, len(mods))
	for _, m := range mods {
		out = append(out, moduleView{m.Name(), m.Description(), m.Category(), m.RequiredKey()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	type scanRow struct {
		ID   int64
		URL  string
		Date string
	}
	var recent []scanRow
	if scans, err := s.store.Scans().List(8); err == nil {
		for _, sc := range scans {
			recent = append(recent, scanRow{sc.ID, sc.URL, sc.ScanDate.Format("2006-01-02 15:04")})
		}
	}
	mods := registeredModules()
	type tmplView struct {
		Name, Desc, Mode, ModulesCSV string
	}
	var templates []tmplView
	if ts, err := s.store.Templates().List(); err == nil {
		for _, t := range ts {
			templates = append(templates, tmplView{t.Name, t.Description, t.Mode, strings.Join(t.Modules, ",")})
		}
	}
	s.render(w, "index", map[string]any{
		"Modules":     mods,
		"ModuleCount": len(mods),
		"RecentScans": recent,
		"Templates":   templates,
		"CSRF":        csrfToken(r),
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	target, err := safety.ValidateTarget(r.FormValue("target"))
	if err != nil {
		http.Error(w, "invalid target: "+err.Error(), http.StatusBadRequest)
		return
	}
	modules := r.Form["modules"]
	mode := r.FormValue("mode")

	taskID := uuid.NewString()
	if err := s.store.Tasks().Create(taskID, target.URL); err != nil {
		http.Error(w, "could not create task", http.StatusInternalServerError)
		return
	}
	// Run tied to the server root context so shutdown cancels in-flight scans.
	s.runner.StartTask(s.rootCtx, taskID, target, engine.RunOptions{Modules: modules, Mode: mode})

	s.render(w, "progress", map[string]any{"TaskID": taskID, "Target": target.Raw})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	taskID := chi.URLParam(r, "taskID")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(10 * time.Minute)

	for {
		select {
		case <-r.Context().Done(): // client disconnected
			return
		case <-timeout:
			return
		case <-ticker.C:
			task, err := s.store.Tasks().Get(taskID)
			if err != nil {
				fmt.Fprintf(w, "event: progress\ndata: <div class='st-error'>task not found</div>\n\n")
				flusher.Flush()
				return
			}
			done := len(task.CompletedModules)
			fmt.Fprintf(w, "event: progress\ndata: %s\n\n", progressHTML(task.State, done, task.CompletedModules))
			flusher.Flush()

			if task.State == "SUCCESS" {
				scanID := scanIDFromResults(task.Results)
				payload, _ := json.Marshal(map[string]any{"scan_id": scanID})
				fmt.Fprintf(w, "event: done\ndata: %s\n\n", payload)
				flusher.Flush()
				return
			}
			if task.State == "FAILURE" {
				payload, _ := json.Marshal(map[string]any{"error": task.Error})
				fmt.Fprintf(w, "event: done\ndata: %s\n\n", payload)
				flusher.Flush()
				return
			}
		}
	}
}

func progressHTML(state string, done int, completed []string) string {
	chips := ""
	for _, m := range completed {
		chips += fmt.Sprintf("<span class='chip'>✓ %s</span>", template.HTMLEscapeString(m))
	}
	return fmt.Sprintf(
		"<div><span class='pulse'></span> %s — %d modules complete</div><div class='bar'><i style='width:%d%%'></i></div><div>%s</div>",
		template.HTMLEscapeString(state), done, min(done*8+4, 100), chips)
}

func (s *Server) handleView(w http.ResponseWriter, r *http.Request) {
	var id int64
	if _, err := fmt.Sscan(chi.URLParam(r, "id"), &id); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	sc, err := s.store.Scans().Get(id)
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	s.renderResults(w, r, sc.ID, sc.Results, sc.ScanDate)
}

func (s *Server) handleViewByTask(w http.ResponseWriter, r *http.Request) {
	task, err := s.store.Tasks().Get(chi.URLParam(r, "taskID"))
	if err != nil {
		http.Error(w, "task not found", http.StatusNotFound)
		return
	}
	id := scanIDFromResults(task.Results)
	if id > 0 {
		http.Redirect(w, r, fmt.Sprintf("/view/%d", id), http.StatusFound)
		return
	}
	http.Error(w, "scan not ready", http.StatusAccepted)
}

func (s *Server) renderResults(w http.ResponseWriter, r *http.Request, scanID int64, resultsJSON string, date time.Time) {
	var results map[string]any
	if err := json.Unmarshal([]byte(resultsJSON), &results); err != nil {
		http.Error(w, "corrupt results", http.StatusInternalServerError)
		return
	}
	meta, _ := results["_meta"].(map[string]any)
	moduleStatus, _ := meta["module_status"].(map[string]any)
	catByName := moduleCategories()

	type modView struct {
		Name, Pretty, Category, Status, RawJSON string
		Data                                    any
	}
	var mods []modView
	names := make([]string, 0, len(results))
	for k := range results {
		if k != "_meta" && k != "_summary" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		status := "success"
		if moduleStatus != nil {
			if st, ok := moduleStatus[name].(string); ok {
				status = st
			}
		}
		pretty, _ := json.MarshalIndent(results[name], "", "  ")
		mods = append(mods, modView{
			Name: name, Pretty: prettifyKey(name), Category: catByName[name],
			Status: status, Data: results[name], RawJSON: string(pretty),
		})
	}

	// Severity-sorted findings overview.
	findings := export.ExtractFindings(results)
	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(findings, func(i, j int) bool {
		return sevRank[findings[i].Severity] < sevRank[findings[j].Severity]
	})

	target, _ := meta["target"].(string)
	fromCache, _ := meta["from_cache"].(bool)
	sum, _ := results["_summary"].(map[string]any)

	// Analyst notes + a compare-with-previous affordance.
	type noteView struct {
		ID                 int64
		Author, Note, When string
	}
	var notes []noteView
	if ns, err := s.store.Notes().List(scanID); err == nil {
		for _, n := range ns {
			notes = append(notes, noteView{n.ID, n.Author, n.Note, n.CreatedAt.Format("2006-01-02 15:04")})
		}
	}
	var prevID int64
	if sc, err := s.store.Scans().Get(scanID); err == nil {
		if pid, ok := s.store.Scans().PreviousForURL(sc.URL, scanID); ok {
			prevID = pid
		}
	}

	s.render(w, "results", map[string]any{
		"ScanID":        scanID,
		"Target":        target,
		"ScanDate":      date.Format("2006-01-02 15:04"),
		"FromCache":     fromCache,
		"Modules":       mods,
		"Findings":      findings,
		"Notes":         notes,
		"PrevScanID":    prevID,
		"CSRF":          csrfToken(r),
		"RiskScore":     numToInt(sum["risk_score"]),
		"RiskLevel":     strOrDefault(sum["risk_level"], "info"),
		"TotalFindings": numToInt(sum["total_findings"]),
		"Critical":      numToInt(sum["critical"]),
		"High":          numToInt(sum["high"]),
		"Medium":        numToInt(sum["medium"]),
		"Low":           numToInt(sum["low"]),
	})
}

// moduleCategories maps module name -> category for result rendering.
func moduleCategories() map[string]string {
	out := map[string]string{}
	for _, m := range engine.All() {
		out[m.Name()] = m.Category()
	}
	return out
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	type scanRow struct {
		ID   int64
		URL  string
		Date string
	}
	var rows []scanRow
	if scans, err := s.store.Scans().List(100); err == nil {
		for _, sc := range scans {
			rows = append(rows, scanRow{sc.ID, sc.URL, sc.ScanDate.Format("2006-01-02 15:04")})
		}
	}
	s.render(w, "scans", map[string]any{"Scans": rows})
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	s.render(w, "modules", map[string]any{"Modules": registeredModules()})
}

func (s *Server) handleCampaigns(w http.ResponseWriter, r *http.Request) {
	type row struct {
		ID                 int64
		Name, Status, When string
		Count              int
	}
	var rows []row
	if cs, err := s.store.Campaigns().List(); err == nil {
		for _, c := range cs {
			rows = append(rows, row{c.ID, c.Name, c.Status, c.CreatedAt.Format("2006-01-02 15:04"), len(c.Targets)})
		}
	}
	s.render(w, "campaigns", map[string]any{"Campaigns": rows, "CSRF": csrfToken(r)})
}

func (s *Server) handleCampaignCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "Campaign " + time.Now().Format("2006-01-02 15:04")
	}
	modules := r.Form["modules"]
	mode := r.FormValue("mode")

	var urls []string
	for _, line := range strings.Split(r.FormValue("targets"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if t, err := safety.ValidateTarget(line); err == nil {
			urls = append(urls, t.URL)
		}
	}
	if len(urls) == 0 {
		http.Error(w, "no valid targets", http.StatusBadRequest)
		return
	}
	id, err := s.store.Campaigns().Create(name, urls)
	if err != nil {
		http.Error(w, "could not create campaign", http.StatusInternalServerError)
		return
	}
	// Launch a scan per target (bounded by the engine's worker pool).
	for _, u := range urls {
		t, _ := safety.ValidateTarget(u)
		taskID := uuid.NewString()
		if err := s.store.Tasks().Create(taskID, t.URL); err == nil {
			s.runner.StartTask(s.rootCtx, taskID, t, engine.RunOptions{Modules: modules, Mode: mode})
		}
	}
	http.Redirect(w, r, fmt.Sprintf("/campaign/%d", id), http.StatusSeeOther)
}

func (s *Server) handleCampaignView(w http.ResponseWriter, r *http.Request) {
	var id int64
	if _, err := fmt.Sscan(chi.URLParam(r, "id"), &id); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	c, err := s.store.Campaigns().Get(id)
	if err != nil {
		http.Error(w, "campaign not found", http.StatusNotFound)
		return
	}
	type row struct {
		Target string
		ScanID int64
		Risk   int
		Level  string
		Done   bool
	}
	var rows []row
	done := 0
	for _, u := range c.Targets {
		rv := row{Target: u}
		if sc, ok := s.store.Scans().LatestForURL(u); ok {
			rv.ScanID = sc.ID
			rv.Risk = scanRisk(sc.Results)
			rv.Level = scanLevel(sc.Results)
			rv.Done = true
			done++
		}
		rows = append(rows, rv)
	}
	status := "running"
	if done == len(c.Targets) {
		status = "completed"
		_ = s.store.Campaigns().SetResults(id, map[string]any{"completed": done}, status)
	}
	s.render(w, "campaign", map[string]any{
		"ID": id, "Name": c.Name, "Status": status,
		"Rows": rows, "Done": done, "Total": len(c.Targets),
	})
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	var id int64
	if _, err := fmt.Sscan(chi.URLParam(r, "id"), &id); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	sc, err := s.store.Scans().Get(id)
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	var results map[string]any
	_ = json.Unmarshal([]byte(sc.Results), &results)
	g := buildGraph(results)
	b, _ := json.Marshal(g)
	s.render(w, "graph", map[string]any{
		"ScanID":    id,
		"Target":    scanTarget(sc.Results),
		"GraphJSON": template.JS(b),
		"NodeCount": len(g.Nodes),
		"EdgeCount": len(g.Edges),
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	c := s.cfg
	type keyRow struct {
		Name, Env, Masked string
		Set               bool
	}
	mk := func(name, env, val string) keyRow {
		return keyRow{Name: name, Env: env, Masked: c.Mask(val), Set: val != ""}
	}
	intel := []keyRow{
		mk("VirusTotal", "VT_API_KEY", c.VTKey), mk("Shodan", "SHODAN_API_KEY", c.ShodanKey),
		mk("AbuseIPDB", "ABUSEIPDB_API_KEY", c.AbuseIPDBKey), mk("GreyNoise", "GREYNOISE_API_KEY", c.GreyNoiseKey),
		mk("URLScan", "URLSCAN_API_KEY", c.URLScanKey), mk("SecurityTrails", "SECURITYTRAILS_API_KEY", c.SecurityTrailsKey),
		mk("AlienVault OTX", "OTX_API_KEY", c.OTXKey), mk("GitHub", "GITHUB_TOKEN", c.GitHubToken),
		mk("Censys ID", "CENSYS_API_ID", c.CensysID), mk("Hunter.io", "HUNTER_API_KEY", c.HunterKey),
		mk("HIBP", "HIBP_API_KEY", c.HIBPKey), mk("FullHunt", "FULLHUNT_API_KEY", c.FullHuntKey),
	}
	ai := []keyRow{
		mk("Gemini", "GEMINI_API_KEY", c.GeminiKey), mk("OpenAI", "OPENAI_API_KEY", c.OpenAIKey),
		mk("Anthropic", "ANTHROPIC_API_KEY", c.AnthropicKey),
	}
	notif := []keyRow{
		mk("Slack", "SLACK_WEBHOOK_URL", c.SlackWebhook), mk("Discord", "DISCORD_WEBHOOK_URL", c.DiscordWebhook),
		mk("Teams", "TEAMS_WEBHOOK_URL", c.TeamsWebhook), mk("Telegram", "TELEGRAM_BOT_TOKEN", c.TelegramBotToken),
	}
	// API keys + recent audit (enterprise).
	type apiKeyRow struct {
		Name, Role, Created, LastUsed string
		Active                        bool
	}
	var keys []apiKeyRow
	if ks, err := s.store.APIKeys().List(); err == nil {
		for _, k := range ks {
			last := "never"
			if k.LastUsed != nil {
				last = k.LastUsed.Format("2006-01-02 15:04")
			}
			keys = append(keys, apiKeyRow{k.Name, k.Role, k.CreatedAt.Format("2006-01-02"), last, k.Active})
		}
	}
	type auditRow struct{ When, User, Action, Details, IP string }
	var audit []auditRow
	if es, err := s.store.Audit().Recent(20); err == nil {
		for _, e := range es {
			audit = append(audit, auditRow{e.Timestamp.Format("01-02 15:04:05"), e.User, e.Action, e.Details, e.IP})
		}
	}

	s.render(w, "settings", map[string]any{
		"App": map[string]any{
			"Version": c.Version, "Host": c.Host, "Port": c.Port, "DBPath": c.DBPath,
			"CacheTTL": c.CacheTTL, "AllowInternal": c.AllowInternal, "AIPrimary": c.AIPrimary,
			"AlertThreshold": c.AlertThreshold, "MaxConcurrentScans": c.MaxConcurrentScans,
			"APIRateLimit": c.APIRateLimit,
		},
		"Intel": intel, "AI": ai, "Notif": notif,
		"AIStatus":    s.ai.Status(),
		"ModuleCount": len(engine.Names()),
		"APIAuth":     c.APIAuthEnabled, "AuditOn": c.AuditLogEnabled,
		"APIKeys": keys, "Audit": audit,
	})
}

func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	var a, b int64
	if _, err := fmt.Sscan(chi.URLParam(r, "a"), &a); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if _, err := fmt.Sscan(chi.URLParam(r, "b"), &b); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	scA, errA := s.store.Scans().Get(a)
	scB, errB := s.store.Scans().Get(b)
	if errA != nil || errB != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	fA := findingKeys(scA.Results)
	fB := findingKeys(scB.Results)
	type fv struct{ Severity, Title, Module string }
	var added, removed []fv
	for k, v := range fB {
		if _, ok := fA[k]; !ok {
			added = append(added, fv{v.Severity, v.Title, v.Module})
		}
	}
	for k, v := range fA {
		if _, ok := fB[k]; !ok {
			removed = append(removed, fv{v.Severity, v.Title, v.Module})
		}
	}
	sortFV := func(s []fv) {
		rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
		sort.SliceStable(s, func(i, j int) bool { return rank[s[i].Severity] < rank[s[j].Severity] })
	}
	sortFV(added)
	sortFV(removed)
	s.render(w, "compare", map[string]any{
		"A": a, "B": b,
		"ATarget": scanTarget(scA.Results), "BTarget": scanTarget(scB.Results),
		"ADate": scA.ScanDate.Format("2006-01-02 15:04"), "BDate": scB.ScanDate.Format("2006-01-02 15:04"),
		"Added": added, "Removed": removed,
		"RiskA": scanRisk(scA.Results), "RiskB": scanRisk(scB.Results),
	})
}

func (s *Server) handleAddNote(w http.ResponseWriter, r *http.Request) {
	var id int64
	if _, err := fmt.Sscan(chi.URLParam(r, "id"), &id); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	note := strings.TrimSpace(r.FormValue("note"))
	if note != "" {
		_, _ = s.store.Notes().Add(id, note, strings.TrimSpace(r.FormValue("author")))
	}
	http.Redirect(w, r, fmt.Sprintf("/view/%d", id), http.StatusSeeOther)
}

func (s *Server) handleDeleteNote(w http.ResponseWriter, r *http.Request) {
	var id int64
	if _, err := fmt.Sscan(chi.URLParam(r, "id"), &id); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	scanID := r.URL.Query().Get("scan")
	_ = s.store.Notes().Delete(id)
	if scanID != "" {
		http.Redirect(w, r, "/view/"+scanID, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/scans", http.StatusSeeOther)
}

func (s *Server) handleScheduled(w http.ResponseWriter, r *http.Request) {
	type row struct {
		ID                  int64
		URL, Mode, Services string
		IntervalMinutes     int
		NextRun, LastRun    string
	}
	var rows []row
	if scheds, err := s.store.Schedules().List(); err == nil {
		for _, sc := range scheds {
			last := "never"
			if sc.LastRun != nil {
				last = sc.LastRun.Format("2006-01-02 15:04")
			}
			rows = append(rows, row{
				ID: sc.ID, URL: sc.URL, Mode: sc.Mode, Services: sc.Services,
				IntervalMinutes: sc.IntervalMinutes,
				NextRun:         sc.NextRun.Format("2006-01-02 15:04"), LastRun: last,
			})
		}
	}
	s.render(w, "scheduled", map[string]any{
		"Schedules": rows, "Modules": registeredModules(), "CSRF": csrfToken(r),
	})
}

func (s *Server) handleScheduleCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	target, err := safety.ValidateTarget(r.FormValue("target"))
	if err != nil {
		http.Error(w, "invalid target: "+err.Error(), http.StatusBadRequest)
		return
	}
	interval, _ := strconv.Atoi(r.FormValue("interval_minutes"))
	if interval < 1 {
		interval = 60
	}
	services, _ := json.Marshal(r.Form["modules"])
	if _, err := s.store.Schedules().Create(target.URL, string(services), r.FormValue("mode"), interval); err != nil {
		http.Error(w, "could not create schedule", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/scheduled", http.StatusSeeOther)
}

func (s *Server) handleScheduleDelete(w http.ResponseWriter, r *http.Request) {
	var id int64
	if _, err := fmt.Sscan(chi.URLParam(r, "id"), &id); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	_ = s.store.Schedules().Delete(id)
	http.Redirect(w, r, "/scheduled", http.StatusSeeOther)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	active, _ := s.store.Tasks().ActiveCount()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"version":      s.cfg.Version,
		"modules":      len(engine.Names()),
		"active_scans": active,
	})
}

func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	var id int64
	if _, err := fmt.Sscan(chi.URLParam(r, "id"), &id); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	sc, err := s.store.Scans().Get(id)
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=obscura-scan-%d.json", id))
	_, _ = w.Write([]byte(sc.Results))
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	format := chi.URLParam(r, "format")
	var id int64
	if _, err := fmt.Sscan(chi.URLParam(r, "id"), &id); err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	sc, err := s.store.Scans().Get(id)
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	var results map[string]any
	if err := json.Unmarshal([]byte(sc.Results), &results); err != nil {
		http.Error(w, "corrupt results", http.StatusInternalServerError)
		return
	}
	meta, _ := results["_meta"].(map[string]any)
	target, _ := meta["target"].(string)
	es := export.Scan{ID: sc.ID, Target: target, ScanDate: sc.ScanDate, Results: results}

	var body []byte
	var ctype, ext string
	switch format {
	case "csv":
		body, ctype, ext = export.CSV(es), "text/csv", "csv"
	case "stix":
		body, ctype, ext = export.STIX(es), "application/json", "stix.json"
	case "splunk-cim":
		body, ctype, ext = export.SplunkCIM(es), "application/x-ndjson", "splunk.ndjson"
	case "qradar-leef":
		body, ctype, ext = export.QRadarLEEF(es), "text/plain", "leef.log"
	case "elastic-ecs":
		body, ctype, ext = export.ElasticECS(es), "application/x-ndjson", "ecs.ndjson"
	case "pdf":
		logo, _ := fs.ReadFile(web.Static, "static/img/logo.png")
		body, ctype, ext = export.PDF(es, logo), "application/pdf", "pdf"
	case "docx":
		body, ctype, ext = export.DOCX(es), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"
	default:
		http.Error(w, "unknown export format", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=obscura-scan-%d.%s", id, ext))
	_, _ = w.Write(body)
}

func (s *Server) handleAPITask(w http.ResponseWriter, r *http.Request) {
	task, err := s.store.Tasks().Get(chi.URLParam(r, "taskID"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "task not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                task.ID,
		"url":               task.URL,
		"state":             task.State,
		"completed_modules": task.CompletedModules,
		"error":             task.Error,
	})
}

// ---- AI copilot handlers ----

func (s *Server) handleAIStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ai.Status())
}

func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Messages []ai.Message `json:"messages"`
		ScanID   int64        `json:"scan_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request"})
		return
	}
	var scanContext map[string]any
	if req.ScanID > 0 {
		if sc, err := s.store.Scans().Get(req.ScanID); err == nil {
			_ = json.Unmarshal([]byte(sc.Results), &scanContext)
		}
	}
	writeJSON(w, http.StatusOK, s.ai.Chat(r.Context(), req.Messages, scanContext))
}

func (s *Server) handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	var id int64
	if _, err := fmt.Sscan(chi.URLParam(r, "id"), &id); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad id"})
		return
	}
	sc, err := s.store.Scans().Get(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "scan not found"})
		return
	}
	var results map[string]any
	_ = json.Unmarshal([]byte(sc.Results), &results)
	writeJSON(w, http.StatusOK, s.ai.AnalyzeScan(r.Context(), results, sc.URL))
}

// ---- small utilities ----

func scanIDFromResults(resultsJSON string) int64 {
	if resultsJSON == "" {
		return 0
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(resultsJSON), &m); err != nil {
		return 0
	}
	meta, _ := m["_meta"].(map[string]any)
	if meta == nil {
		return 0
	}
	if f, ok := meta["scan_id"].(float64); ok {
		return int64(f)
	}
	return 0
}

type findingKey struct{ Severity, Title, Module string }

// findingKeys extracts findings from a results JSON string, keyed for diffing.
func findingKeys(resultsJSON string) map[string]findingKey {
	out := map[string]findingKey{}
	var results map[string]any
	if json.Unmarshal([]byte(resultsJSON), &results) != nil {
		return out
	}
	for _, f := range export.ExtractFindings(results) {
		k := f.Module + "|" + f.Title + "|" + f.Severity
		out[k] = findingKey{f.Severity, f.Title, f.Module}
	}
	return out
}

func scanTarget(resultsJSON string) string {
	var results map[string]any
	_ = json.Unmarshal([]byte(resultsJSON), &results)
	if meta, ok := results["_meta"].(map[string]any); ok {
		if t, ok := meta["target"].(string); ok {
			return t
		}
	}
	return ""
}

func scanRisk(resultsJSON string) int {
	var results map[string]any
	_ = json.Unmarshal([]byte(resultsJSON), &results)
	if sum, ok := results["_summary"].(map[string]any); ok {
		return numToInt(sum["risk_score"])
	}
	return 0
}

func scanLevel(resultsJSON string) string {
	var results map[string]any
	_ = json.Unmarshal([]byte(resultsJSON), &results)
	if sum, ok := results["_summary"].(map[string]any); ok {
		if l, ok := sum["risk_level"].(string); ok {
			return l
		}
	}
	return "info"
}

func numToInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func strOrDefault(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

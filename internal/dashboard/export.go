package dashboard

// The AI-ready export. This file assembles the report from what is already known - the cached
// snapshot, the last completed diagnostics run, the TTL manager's own view, the event ring -
// and hands the result through internal/diagreport's redactor.
//
// Three rules are structural here:
//
//   - Nothing leaves the machine. The export writes two files under the configured output
//     directory when the user asks for that, and nothing else ever touches the network.
//   - What the report does not have, it says. A missing snapshot, a failed TTL read or a
//     diagnostics run that never happened each become a caveat in the document rather than
//     silence that reads like a clean bill of health.
//   - The placeholder-to-value mapping (Entries) is returned to the caller for display and is
//     never part of either saved file.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"net-merge/internal/appcfg"
	"net-merge/internal/diag"
	"net-merge/internal/diagreport"
	"net-merge/internal/logx"
	"net-merge/internal/platform"
	"net-merge/internal/ttlmgr"
)

func (s *Server) handleExportStart(w http.ResponseWriter, r *http.Request) {
	j := s.startJob("export", s.exportFn)
	logx.Eventf(logx.LevelInfo, "dashboard.export", "diagnostic export %s started", j.id)
	writeJSON(w, http.StatusAccepted, j.view())
}

func (s *Server) handleExportGet(w http.ResponseWriter, r *http.Request) {
	s.jobGet(w, r, "export")
}

// handleExportSave writes the already-rendered artifacts to disk. The redacted bytes are what
// get written; the visibility mapping stays in memory and on the user's screen.
func (s *Server) handleExportSave(w http.ResponseWriter, r *http.Request) {
	var req cancelRequest
	if err := decodeBody(r, &req); err != nil {
		fail(w, http.StatusBadRequest, "dashboard_bad_request", "the request body is not valid JSON", err.Error())
		return
	}
	j, ok := s.jobs.get(req.ID)
	if !ok || j.kind != "export" {
		fail(w, http.StatusNotFound, "dashboard_job_unknown", fmt.Sprintf("no export job with id %q", req.ID), nil)
		return
	}
	e := j.exportCopy()
	if e == nil {
		fail(w, http.StatusConflict, "dashboard_job_not_done", "the export has not finished yet", nil)
		return
	}
	dir, err := s.exportDir()
	if err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_export_dir", "the output directory could not be created", err.Error())
		return
	}
	txtPath, jsonPath := diagreport.Bundle{BaseName: e.BaseName}.WriteName(dir)
	if err := os.WriteFile(txtPath, []byte(e.Text), 0o600); err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_export_write", "the text report could not be written", err.Error())
		return
	}
	if err := os.WriteFile(jsonPath, []byte(e.JSON), 0o600); err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_export_write", "the JSON report could not be written", err.Error())
		return
	}
	j.markSaved([]string{txtPath, jsonPath})
	logx.Eventf(logx.LevelInfo, "dashboard.export.save", "diagnostic export saved as %s (.txt and .json)", e.BaseName)
	writeJSON(w, http.StatusOK, map[string]any{"saved": []string{txtPath, jsonPath}})
}

// exportFn is the background job: assemble, render, redact.
func (s *Server) exportFn(ctx context.Context) (any, error) {
	settings, _, err := s.loadSettings()
	if err != nil {
		return nil, fmt.Errorf("the settings file could not be read, so the export's privacy policy is unknown: %w", err)
	}
	limits := diagreport.DefaultLimits()
	var caveats []string

	snap, _, snapErr := s.cached()
	switch {
	case snap == nil:
		caveats = append(caveats, "no adapter snapshot was available when this report was generated, so it contains no interface, route or counter data")
	case snapErr != "":
		caveats = append(caveats, "the most recent adapter snapshot attempt failed ("+snapErr+"); the inventory below is from an earlier read")
	}

	var ttl *ttlmgr.Report
	if s.deps.TTL != nil {
		rep, err := s.deps.TTL.Inspect(ctx, s.ifaces())
		if err != nil {
			caveats = append(caveats, "the TTL/hop-limit settings could not be read for this report: "+err.Error())
		} else {
			ttl = &rep
		}
	} else {
		caveats = append(caveats, "the TTL manager is not available in this environment, so this report has no TTL/hop-limit section")
	}

	var logs []logx.Event
	if s.deps.Logs != nil {
		newestFirst := s.deps.Logs.Search(logx.Filter{}, limits.Logs)
		logs = make([]logx.Event, 0, len(newestFirst))
		// The renderer reads them top to bottom, so oldest first is what a reader wants.
		for i := len(newestFirst) - 1; i >= 0; i-- {
			logs = append(logs, newestFirst[i])
		}
	}

	var run diag.RunResult
	if j := s.jobs.lastDone("diag"); j != nil {
		if r := j.diagResult(); r != nil {
			run = *r
		}
	} else {
		caveats = append(caveats, "no diagnostics run has been completed yet, so this report contains no test results; run the diagnostic centre first if the report should carry evidence")
	}

	doc := diagreport.Build(diagreport.Options{
		Now:      s.now(),
		Version:  s.cfg.Version,
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
		Elevated: platform.IsAdmin(),
		StateDir: s.cfg.StateDir,
		Snapshot: snap,
		Run:      run,
		Engine:   s.reportEngineView(),
		TTL:      ttl,
		Logs:     logs,
		Limits:   limits,
	})
	doc.Caveats = append(doc.Caveats, caveats...)

	b, err := doc.Bundle(s.policy(settings))
	if err != nil {
		return nil, err
	}
	return exportResult{
		BaseName: b.BaseName,
		Text:     string(b.Text),
		JSON:     string(b.JSON),
		Counts:   b.Counts,
		Entries:  b.Entries,
	}, nil
}

// reportEngineView converts the engine's status file into the report's view of it. The
// distinction that matters: the file existing is what "running" means here, and no process
// check is invented on top of it.
func (s *Server) reportEngineView() *diagreport.EngineView {
	st, on := s.engine()
	if !on {
		return &diagreport.EngineView{Running: false}
	}
	return &diagreport.EngineView{
		Running: true,
		Mode:    st.Mode,
		V6:      st.V6,
		Since:   st.Since,
		PID:     st.PID,
		NICs:    st.NICs,
	}
}

// policy maps the user's privacy settings to the redactor's rules. The mapping itself lives in
// diagreport.PolicyFromPrivacy so the CLI's export and the dashboard's export cannot diverge;
// adapter names are passed as extra literals when the user asked for them to be removed.
func (s *Server) policy(cfg appcfg.Config) diagreport.Policy {
	var extra []string
	if cfg.Privacy.RedactAdapterNames {
		if snap, _, _ := s.cached(); snap != nil {
			for _, a := range snap.Adapters {
				if a.Name != "" {
					extra = append(extra, a.Name)
				}
			}
		}
	}
	return diagreport.PolicyFromPrivacy(cfg.Privacy, extra...)
}

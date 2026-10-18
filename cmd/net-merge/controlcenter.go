package main

// The Control Center's command surface: the dashboard, the diagnostics CLI and the TTL CLI.
//
// All three share one construction path (controlCenter) so they cannot disagree about where the
// state lives, which profile is active, or how the inventory is read. The dashboard is the
// interactive surface; the `diag` and `ttl` commands are the scriptable mirrors of it. Where a
// command can change a system setting (ttl apply/restore), it goes through the same manager the
// dashboard uses, with the same dry-run/confirm gate.
//
// Nothing in this file invents a second engine control path: the dashboard and the CLI both turn
// the engine on and off by writing the same marker files state.SendMarker writes, which is what
// `net-merge on|off` already does.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"net-merge/internal/appcfg"
	"net-merge/internal/dashboard"
	"net-merge/internal/diag"
	"net-merge/internal/diagreport"
	"net-merge/internal/inventory"
	"net-merge/internal/logx"
	"net-merge/internal/platform"
	"net-merge/internal/state"
	"net-merge/internal/ttlmgr"
)

// controlCenter is the shared state of the three commands.
type controlCenter struct {
	stateDir    string
	settingsDir string
	logsDir     string

	// cfg is the settings file's content. cfgErr records a file that could not be read; the
	// defaults are used for this run and the error is shown, never swallowed.
	cfg    appcfg.Config
	cfgErr error

	collector *inventory.Collector
	store     *ttlmgr.Store
	manager   *ttlmgr.Manager
	registry  *diag.Registry

	logFile *logx.RotatingFile
}

// newControlCenter builds the shared pieces and starts logging. The settings file lives beside
// the engine's state so a single directory holds everything this application persists.
func newControlCenter() *controlCenter {
	stateDir := state.DefaultDir()
	cc := &controlCenter{
		stateDir:    stateDir,
		settingsDir: stateDir,
		logsDir:     filepath.Join(stateDir, "logs"),
	}
	cfg, _, err := appcfg.Load(stateDir)
	cc.cfg, cc.cfgErr = cfg, err
	if err != nil {
		fmt.Fprintf(os.Stderr, "net-merge: settings: %v\nnet-merge: using defaults for this run; the Settings section will show and fix the file\n", err)
	}

	if lv, ok := logx.ParseLevel(cfg.Logging.Level); ok {
		logx.SetLevel(lv)
	}
	if cfg.Logging.RingEvents > 0 {
		logx.SetRingCapacity(cfg.Logging.RingEvents)
	}
	if err := os.MkdirAll(cc.logsDir, 0o755); err == nil {
		if rf, err := logx.OpenRotating(filepath.Join(cc.logsDir, "net-merge.log"), cfg.Logging.MaxBytes, cfg.Logging.MaxFiles); err == nil {
			cc.logFile = rf
			logx.SetOutput(io.MultiWriter(os.Stderr, rf))
		} else {
			logx.Eventf(logx.LevelWarn, "cc.logfile", "log file unavailable: %v", err)
		}
	}

	cc.collector = inventory.NewCollector(inventory.NewPlatformSource())
	cc.store = ttlmgr.NewStore(filepath.Join(stateDir, "ttl"))
	cc.manager = ttlmgr.NewManager(cc.store, ttlmgr.NewBackend(ttlmgr.NewExecRunner()))
	cc.registry = diag.NewRegistry(cc.diagEnv())
	return cc
}

func (c *controlCenter) Close() {
	if c.logFile != nil {
		_ = c.logFile.Close()
	}
}

// Snapshot implements dashboard.Snapshotter: the dashboard's monitor loop calls it, and the
// diagnostics environment is given the same function, so a run and the page see one system.
func (c *controlCenter) Snapshot(ctx context.Context) (*inventory.Snapshot, error) {
	opts := inventory.Options{}
	if p, ok := c.cfg.Profiles[c.cfg.ActiveProfile]; ok {
		opts.Include = p.Engine.Include
		opts.Exclude = p.Engine.Exclude
	}
	// The engine's own status file says which adapters it is using. That is the only honest
	// source for "in use": a process check would be a guess.
	if st, on := state.Read(c.stateDir); on {
		used := make(map[string]bool, len(st.NICs))
		assigned := make(map[string]int, len(st.NICs))
		for _, n := range st.NICs {
			used[n.Name] = true
			if n.Active > 0 {
				assigned[n.Name] = int(n.Active)
			}
		}
		opts.EngineUsed = used
		opts.EngineAssigned = assigned
	}
	return c.collector.Snapshot(ctx, opts)
}

// diagEnv is the environment the diagnostics registry reads. InspectTTL is wired to the real
// manager here, which is what keeps the diagnostic package from ever constructing one itself.
func (c *controlCenter) diagEnv() *diag.Env {
	env := diag.NewEnv()
	env.Snapshot = c.Snapshot
	env.StateDir = c.stateDir
	env.AppVersion = version
	env.Self = selfPath()
	env.Config = c.cfg.Diagnostics
	env.IsAdmin = platform.IsAdmin()
	env.InspectTTL = func(ctx context.Context, ifaces []ttlmgr.IfaceInfo) (ttlmgr.Report, error) {
		return c.manager.Inspect(ctx, ifaces)
	}
	return env
}

func selfPath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return p
}

// ifacesFrom maps a snapshot's adapters to the manager's interface list. An adapter with no
// index is not addressable by the platform's commands and is left out rather than guessed at.
func ifacesFrom(snap *inventory.Snapshot) []ttlmgr.IfaceInfo {
	if snap == nil {
		return nil
	}
	out := make([]ttlmgr.IfaceInfo, 0, len(snap.Adapters))
	for _, a := range snap.Adapters {
		if a.Index == 0 {
			continue
		}
		out = append(out, ttlmgr.IfaceInfo{Index: a.Index, Name: a.Name})
	}
	return out
}

// ttlAPI adapts the manager and its store to the dashboard's TTL surface.
type ttlAPI struct {
	m *ttlmgr.Manager
	s *ttlmgr.Store
}

func (t ttlAPI) Inspect(ctx context.Context, ifaces []ttlmgr.IfaceInfo) (ttlmgr.Report, error) {
	return t.m.Inspect(ctx, ifaces)
}
func (t ttlAPI) Apply(ctx context.Context, req ttlmgr.ApplyRequest) (ttlmgr.Outcome, error) {
	return t.m.Apply(ctx, req)
}
func (t ttlAPI) Restore(ctx context.Context, req ttlmgr.RestoreRequest) (ttlmgr.Outcome, error) {
	return t.m.Restore(ctx, req)
}
func (t ttlAPI) SaveConfig(c ttlmgr.Config) error { return t.s.SaveConfig(c) }
func (t ttlAPI) History(limit int) ([]ttlmgr.Event, error) {
	return t.s.History(limit)
}

// logxReader adapts the log package's ring to the dashboard's reader interface.
type logxReader struct{}

func (logxReader) Events(since uint64, min logx.Level, limit int) ([]logx.Event, uint64) {
	return logx.Events(since, min, limit)
}
func (logxReader) Search(f logx.Filter, limit int) []logx.Event { return logx.Search(f, limit) }

// --- net-merge dashboard -------------------------------------------------------------------------

func cmdDashboard(args []string) {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	listen := fs.String("listen", "", "loopback listen address (default: the one in settings)")
	port := fs.Int("port", 0, "listen port (0 picks a free one)")
	interval := fs.Duration("interval", 0, "snapshot interval (default: the one in settings)")
	open := fs.Bool("open", false, "open the dashboard in the default browser")
	noOpen := fs.Bool("no-open", false, "do not open a browser even when settings ask for it")
	fs.Parse(args)

	cc := newControlCenter()
	defer cc.Close()

	addr := *listen
	if addr == "" {
		addr = cc.cfg.Dashboard.Listen
	}
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if *port != 0 {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = "127.0.0.1"
		}
		addr = net.JoinHostPort(host, strconv.Itoa(*port))
	}
	iv := *interval
	if iv <= 0 && cc.cfg.Dashboard.IntervalMs > 0 {
		iv = time.Duration(cc.cfg.Dashboard.IntervalMs) * time.Millisecond
	}

	srv, err := dashboard.New(dashboard.Config{
		Version:     version,
		Listen:      addr,
		Interval:    iv,
		OutputDir:   "outputs",
		StateDir:    cc.stateDir,
		SettingsDir: cc.settingsDir,
	}, dashboard.Deps{
		Snapshot: cc,
		TTL:      ttlAPI{m: cc.manager, s: cc.store},
		Diag:     cc.registry,
		Logs:     logxReader{},
	})
	if err != nil {
		die(err)
	}
	if _, err := srv.Start(); err != nil {
		die(err)
	}
	defer srv.Close(context.Background())

	url := srv.URL()
	fmt.Printf("NetMerge Control Center\n\n  %s\n\n", url)
	fmt.Println("  The page is local-only: it listens on loopback and every request carries the")
	fmt.Println("  access token above. Nothing is uploaded anywhere; the export writes files and")
	fmt.Println("  shows you exactly what it redacted before you share them.")
	fmt.Println()
	fmt.Println("  Turn the engine on and off from the page, or keep using the tray. Both write")
	fmt.Println("  the same control files, so they cannot disagree.")
	fmt.Println()
	fmt.Println("  Ctrl+C stops the dashboard (it does not stop the bonding engine).")
	fmt.Println()

	if *open || (cc.cfg.Dashboard.OpenBrowser && !*noOpen) {
		if err := openBrowser(url); err != nil {
			fmt.Fprintf(os.Stderr, "net-merge: could not open a browser (%v); open the address above by hand\n", err)
		}
	}
	logx.Eventf(logx.LevelInfo, "cc.dashboard", "dashboard started on %s", srv.Addr())

	stop := make(chan os.Signal, 2)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	sig := <-stop
	fmt.Printf("\nnet-merge: dashboard stopping (%s); the engine, if it was on, keeps running\n", sig)
}

// --- net-merge diag ------------------------------------------------------------------------------

func cmdDiag(args []string) {
	fs := flag.NewFlagSet("diag", flag.ExitOnError)
	only := fs.String("only", "", "comma-separated check ids to run (default: every supported check)")
	category := fs.String("category", "", "comma-separated categories to run")
	asJSON := fs.Bool("json", false, "print the machine-readable run result")
	exportDir := fs.String("export", "", "write the redacted text and JSON report into this directory")
	timeout := fs.Duration("timeout", 0, "overall time budget for the run (0 = the settings' per-check timeouts)")
	fs.Parse(args)

	cc := newControlCenter()
	defer cc.Close()

	ctx := context.Background()
	var cancel context.CancelFunc
	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	// One snapshot for the whole run, taken once so every check judged the same instant.
	snap, err := cc.Snapshot(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "net-merge: the adapter inventory could not be read: %v\n", err)
		fmt.Fprintln(os.Stderr, "net-merge: running the checks that do not need it; the report will say the inventory was missing")
	}

	env := cc.diagEnv()
	env.SnapshotValue = snap
	reg := diag.NewRegistry(env)

	opts := diag.Options{
		Concurrency:     4,
		PerCheckTimeout: time.Duration(cc.cfg.Diagnostics.TracerouteTimeoutMs+30_000) * time.Millisecond,
		Disabled:        cc.cfg.Diagnostics.DisabledChecks,
	}
	if *only != "" {
		opts.Only = splitList(*only)
	}
	if *category != "" {
		for _, c := range splitList(*category) {
			opts.Categories = append(opts.Categories, diag.Category(c))
		}
	}

	run := reg.RunAll(ctx, opts)

	if *asJSON {
		b, _ := json.MarshalIndent(run, "", "  ")
		fmt.Println(string(b))
	} else {
		printRun(run)
	}

	if *exportDir != "" {
		doc, err := cc.buildDocument(ctx, snap, run)
		if err != nil {
			fmt.Fprintf(os.Stderr, "net-merge: could not build the report: %v\n", err)
			os.Exit(1)
		}
		bundle, err := doc.Bundle(diagreport.PolicyFromPrivacy(cc.cfg.Privacy, extraAdapterNames(snap)...))
		if err != nil {
			fmt.Fprintf(os.Stderr, "net-merge: could not render the report: %v\n", err)
			os.Exit(1)
		}
		if err := os.MkdirAll(*exportDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "net-merge: %v\n", err)
			os.Exit(1)
		}
		txt, js := bundle.WriteName(*exportDir)
		if err := os.WriteFile(txt, bundle.Text, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "net-merge: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(js, bundle.JSON, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "net-merge: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nreport written (already redacted):\n  %s\n  %s\n", txt, js)
		fmt.Printf("redacted %d value(s). The placeholder-to-value mapping is shown here and is NOT in the files:\n", bundle.Counts.Total)
		printEntries(bundle.Entries)
	}
}

func extraAdapterNames(snap *inventory.Snapshot) []string {
	if snap == nil {
		return nil
	}
	out := make([]string, 0, len(snap.Adapters))
	for _, a := range snap.Adapters {
		if a.Name != "" {
			out = append(out, a.Name)
		}
	}
	return out
}

// buildDocument assembles the report from the run plus the same views the dashboard's export
// uses: the engine's status file, the TTL manager's report, the recent events and the inventory.
func (c *controlCenter) buildDocument(ctx context.Context, snap *inventory.Snapshot, run diag.RunResult) (*diagreport.Document, error) {
	var caveats []string
	var ttlReport *ttlmgr.Report
	if rep, err := c.manager.Inspect(ctx, ifacesFrom(snap)); err != nil {
		caveats = append(caveats, "the TTL/hop-limit settings could not be read for this report: "+err.Error())
	} else {
		ttlReport = &rep
	}
	newestFirst := logx.Search(logx.Filter{}, diagreport.DefaultLimits().Logs)
	logs := make([]logx.Event, 0, len(newestFirst))
	for i := len(newestFirst) - 1; i >= 0; i-- {
		logs = append(logs, newestFirst[i])
	}
	engineView := &diagreport.EngineView{Running: false}
	if st, on := state.Read(c.stateDir); on {
		engineView = &diagreport.EngineView{Running: true, Mode: st.Mode, V6: st.V6, Since: st.Since, PID: st.PID, NICs: st.NICs}
	}
	if snap == nil {
		caveats = append(caveats, "no adapter snapshot was available when this report was generated, so it contains no interface, route or counter data")
	}
	doc := diagreport.Build(diagreport.Options{
		Now:      time.Now(),
		Version:  version,
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
		Elevated: platform.IsAdmin(),
		StateDir: c.stateDir,
		Snapshot: snap,
		Run:      run,
		Engine:   engineView,
		TTL:      ttlReport,
		Logs:     logs,
	})
	doc.Caveats = append(doc.Caveats, caveats...)
	return doc, nil
}

func printRun(run diag.RunResult) {
	fmt.Println(run.Summary)
	if len(run.Skipped) > 0 {
		fmt.Println("skipped:")
		for id, why := range run.Skipped {
			fmt.Printf("  %-28s %s\n", id, why)
		}
	}
	fmt.Println()
	for _, res := range run.Results {
		fmt.Printf("[%s] %s (%s)\n  %s\n", res.Status, res.Title, res.ID, res.Summary)
		for _, e := range res.Established {
			fmt.Printf("    establishes: %s\n", e)
		}
		for _, e := range res.Inconclusive {
			fmt.Printf("    cannot establish: %s\n", e)
		}
		if len(res.ErrorCodes) > 0 {
			fmt.Printf("    codes: %s\n", strings.Join(res.ErrorCodes, ", "))
		}
		for _, s := range res.NextSteps {
			fmt.Printf("    next: %s\n", s)
		}
		fmt.Println()
	}
}

func printEntries(entries []diagreport.Entry) {
	if len(entries) == 0 {
		fmt.Println("nothing needed redacting.")
		return
	}
	fmt.Println("what the placeholders stand for (shown here only):")
	for _, en := range entries {
		fmt.Printf("  %-12s %-14s %s\n", en.Placeholder, en.Category, en.Value)
	}
}

// --- net-merge ttl -------------------------------------------------------------------------------

func cmdTTL(args []string) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, ttlUsage)
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "inspect":
		ttlInspect(rest)
	case "config":
		ttlConfig(rest)
	case "preview":
		ttlApplyOrRestore(rest, false, true)
	case "apply":
		ttlApplyOrRestore(rest, false, false)
	case "restore":
		ttlApplyOrRestore(rest, true, false)
	case "history":
		ttlHistory(rest)
	default:
		fmt.Fprint(os.Stderr, ttlUsage)
		os.Exit(2)
	}
}

const ttlUsage = `net-merge ttl: the IPv4 TTL / IPv6 hop-limit manager.

  net-merge ttl inspect [-json]           read the current values (never writes)
  net-merge ttl config [flags]            save the opt-in configuration (never writes to the system)
        -enabled=true
        -v4 65                          IPv4 TTL to write while managed
        -v6 65                          IPv6 hop limit to write while managed
        -policy none|list|all-except    which adapters the per-interface policy targets
        -include a,b                    adapter names for -policy list
        -exclude a,b                    adapter names for -policy all-except
  net-merge ttl preview [-json]           show exactly what an apply would change
  net-merge ttl apply -confirm [-json]    apply; refuses without -confirm
  net-merge ttl restore [-confirm] [-only ids] [-json]
                                          put the captured originals back
  net-merge ttl history [-json]           the append-only change history

Both families are opt-in. Nothing here touches DNS record TTLs, traceroute hop counts or any
route: those are reported by 'ttl inspect' under "not these" so they are not confused with the
packet-header values this manager owns. Every write captures the original value first and is
verified by reading it back; a write that cannot be confirmed is reported as unverified.
`

func ttlInspect(args []string) {
	fs := flag.NewFlagSet("ttl inspect", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Parse(args)

	cc := newControlCenter()
	defer cc.Close()
	ctx := context.Background()
	snap, _ := cc.Snapshot(ctx)
	report, err := cc.manager.Inspect(ctx, ifacesFrom(snap))
	if err != nil {
		die(err)
	}
	if *asJSON {
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("mechanism: %s (supported on this host: %v)\n", report.Capabilities.Platform, report.Capabilities.Supported)
	for _, n := range report.Capabilities.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	if report.Elevated {
		fmt.Println("running elevated: yes")
	} else {
		fmt.Printf("running elevated: no (%s)\n", report.Elevation)
	}
	fmt.Println()
	fmt.Println("packet-header settings:")
	if len(report.Settings) == 0 {
		fmt.Println("  (none reported)")
	}
	for _, s := range report.Settings {
		val := "not configured (the platform default applies)"
		if s.Value != nil {
			val = strconv.Itoa(*s.Value)
		}
		writable := "writable"
		if !s.Writable {
			writable = "not writable: " + s.WritableReason
		}
		fmt.Printf("  %-28s %-9s %-14s %-10s %-14s %s  [%s]\n",
			s.ID, s.Kind, s.Family, s.Scope, s.Interface, val, writable)
	}
	fmt.Println()
	fmt.Println("captured originals (what restore puts back):")
	if len(report.Captured) == 0 {
		fmt.Println("  (nothing captured yet)")
	}
	for id, o := range report.Captured {
		val := "not set"
		if o.Value != nil {
			val = strconv.Itoa(*o.Value)
		}
		fmt.Printf("  %-28s %s (explicit: %v, captured %s)\n", id, val, o.Explicit, o.CapturedAt.Format(time.RFC3339))
	}
	if len(report.NotSettings) > 0 {
		fmt.Println()
		fmt.Println("not these (reported so they are not mistaken for the settings above):")
		for _, n := range report.NotSettings {
			fmt.Printf("  %-28s %s - %s\n", n.ID, n.Kind, n.WritableReason)
		}
	}
	if len(report.ReadErrors) > 0 {
		fmt.Println()
		fmt.Println("could not be read:")
		for _, e := range report.ReadErrors {
			fmt.Printf("  %s %s: %s\n", e.Code, e.Setting.ID, e.Message)
		}
	}
}

func ttlConfig(args []string) {
	fs := flag.NewFlagSet("ttl config", flag.ExitOnError)
	enabled := fs.Bool("enabled", false, "record that management is opted in")
	v4 := fs.Int("v4", 0, "IPv4 TTL to write while managed (1..255)")
	v6 := fs.Int("v6", 0, "IPv6 hop limit to write while managed (1..255)")
	policy := fs.String("policy", "", "none|list|all-except")
	include := fs.String("include", "", "comma-separated adapter names for -policy list")
	exclude := fs.String("exclude", "", "comma-separated adapter names for -policy all-except")
	fs.Parse(args)

	cc := newControlCenter()
	defer cc.Close()

	cfg, err := cc.store.LoadConfig()
	if err != nil {
		die(err)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["enabled"] {
		cfg.Enabled = *enabled
	}
	if set["v4"] {
		cfg.BumpIPv4 = *v4
	}
	if set["v6"] {
		cfg.BumpIPv6 = *v6
	}
	if set["policy"] {
		cfg.Policy = ttlmgr.InterfacePolicy(*policy)
	}
	if set["include"] {
		cfg.IncludeIfaces = splitList(*include)
	}
	if set["exclude"] {
		cfg.ExcludeIfaces = splitList(*exclude)
	}
	if err := cfg.Validate(); err != nil {
		die(err)
	}
	if err := cc.store.SaveConfig(cfg); err != nil {
		die(err)
	}
	fmt.Printf("saved %s\n  enabled=%v ipv4=%d ipv6=%d policy=%s\n  include=%v exclude=%v\n",
		cc.store.Dir(), cfg.Enabled, cfg.BumpIPv4, cfg.BumpIPv6, cfg.Policy, cfg.IncludeIfaces, cfg.ExcludeIfaces)
	fmt.Println("Nothing was changed on the system. Use 'net-merge ttl preview' to see what an apply would do.")
}

func ttlApplyOrRestore(args []string, restore, forceDryRun bool) {
	name := "apply"
	if restore {
		name = "restore"
	}
	fs := flag.NewFlagSet("ttl "+name, flag.ExitOnError)
	confirm := fs.Bool("confirm", false, "actually write (without it this is refused; preview first)")
	only := fs.String("only", "", "restore only these setting ids")
	reason := fs.String("reason", "", "reason recorded in the change history")
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Parse(args)

	cc := newControlCenter()
	defer cc.Close()
	ctx := context.Background()
	snap, _ := cc.Snapshot(ctx)
	ifaces := ifacesFrom(snap)

	req := ttlmgr.ApplyRequest{Ifaces: ifaces, DryRun: forceDryRun || !*confirm, Confirm: *confirm, Reason: *reason}
	if req.Reason == "" {
		req.Reason = "net-merge ttl " + name
	}
	if !forceDryRun && !*confirm {
		fmt.Fprintf(os.Stderr, "net-merge: refusing to write without -confirm.\nRun 'net-merge ttl preview' first: it shows every setting, its current value and what would change.\n")
		os.Exit(1)
	}

	var (
		out ttlmgr.Outcome
		err error
	)
	if restore {
		rreq := ttlmgr.RestoreRequest{Ifaces: ifaces, DryRun: req.DryRun, Confirm: req.Confirm, Reason: req.Reason}
		for _, id := range splitList(*only) {
			rreq.Only = append(rreq.Only, ttlmgr.SettingID(id))
		}
		out, err = cc.manager.Restore(ctx, rreq)
	} else {
		out, err = cc.manager.Apply(ctx, req)
	}
	if err != nil {
		die(err)
	}
	if *asJSON {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}
	verb := "applied"
	if out.DryRun {
		verb = "would be applied"
	}
	fmt.Printf("%s: %d change(s) %s, %d failed", name, out.Applied, verb, out.Failed)
	if out.RolledBack {
		fmt.Print(", rolled back")
	}
	if out.RollbackIncomplete {
		fmt.Print(", ROLLBACK INCOMPLETE")
	}
	fmt.Println()
	for _, ch := range out.Changes {
		from := "(could not be read)"
		if ch.From != nil {
			from = strconv.Itoa(*ch.From)
		}
		verified := "not confirmed"
		if ch.Verified {
			verified = "read back"
		}
		fmt.Printf("  %-28s %s -> %d  [%s, %s] %s\n", ch.Setting.ID, from, ch.To, ch.Outcome, verified, ch.Detail)
	}
	for _, d := range out.RollbackDetail {
		fmt.Printf("  rollback: %s\n", d)
	}
	for _, n := range out.Notes {
		fmt.Printf("  note: %s\n", n)
	}
}

func ttlHistory(args []string) {
	fs := flag.NewFlagSet("ttl history", flag.ExitOnError)
	limit := fs.Int("limit", 100, "how many events")
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Parse(args)

	cc := newControlCenter()
	defer cc.Close()
	evs, err := cc.store.History(*limit)
	if err != nil {
		die(err)
	}
	if *asJSON {
		b, _ := json.MarshalIndent(evs, "", "  ")
		fmt.Println(string(b))
		return
	}
	if len(evs) == 0 {
		fmt.Println("no changes have been recorded.")
		return
	}
	for _, e := range evs {
		from := "-"
		if e.Old != nil {
			from = strconv.Itoa(*e.Old)
		}
		to := "-"
		if e.New != nil {
			to = strconv.Itoa(*e.New)
		}
		line := fmt.Sprintf("%s  %-28s %s -> %s  [%s] %s", e.At.Format(time.RFC3339), e.ID, from, to, e.Outcome, e.Reason)
		if e.Error != "" {
			line += "  error: " + e.Error
		}
		fmt.Println(line)
	}
}

// splitList turns "a, b ,c" into a clean list, dropping empties.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

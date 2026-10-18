package logx

// Tests for the logging surface.
//
// Two properties matter beyond "it logs": the in-memory history must stay bounded and must keep
// events even when the console level hides them (raising the level must not erase evidence), and
// the rotating file must never lose or split a record. The tests reset the package globals
// through t.Cleanup so they do not leak into each other.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// isolate resets the package-level logger for a test and restores the previous settings after.
func isolate(t *testing.T, ringCap int) *bytes.Buffer {
	t.Helper()
	mu.Lock()
	prevOut, prevLevel, prevEvents := out, level, events
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		out, level, events = prevOut, prevLevel, prevEvents
		mu.Unlock()
	})

	buf := &bytes.Buffer{}
	SetOutput(buf)
	SetLevel(LevelDebug)
	SetRingCapacity(ringCap)
	return buf
}

func TestRingKeepsTheNewestEventsOnly(t *testing.T) {
	isolate(t, 3)
	for i := 1; i <= 5; i++ {
		Eventf(LevelInfo, "test", "event %d", i)
	}
	evs := Snapshot()
	if len(evs) != 3 {
		t.Fatalf("ring kept %d events, want 3", len(evs))
	}
	if evs[0].Message != "event 3" || evs[2].Message != "event 5" {
		t.Errorf("the oldest events should be dropped, got %q..%q", evs[0].Message, evs[2].Message)
	}
	// Sequence numbers are monotonic and survive the drop, which is what lets a client use them
	// as a cursor.
	if evs[0].Seq != 3 || evs[2].Seq != 5 {
		t.Errorf("sequence numbers = %d..%d, want 3..5", evs[0].Seq, evs[2].Seq)
	}
}

func TestEventsSinceIsIncremental(t *testing.T) {
	isolate(t, 10)
	for i := 1; i <= 5; i++ {
		Eventf(LevelInfo, "test", "event %d", i)
	}
	all, cursor := Events(0, LevelDebug, 0)
	if len(all) != 5 || cursor != 5 {
		t.Fatalf("initial read = %d events, cursor %d", len(all), cursor)
	}
	next, cursor := Events(cursor, LevelDebug, 0)
	if len(next) != 0 || cursor != 5 {
		t.Fatalf("an up-to-date client should get nothing new, got %d events, cursor %d", len(next), cursor)
	}
	Eventf(LevelInfo, "test", "event 6")
	next, cursor = Events(cursor, LevelDebug, 0)
	if len(next) != 1 || next[0].Message != "event 6" || cursor != 6 {
		t.Fatalf("incremental read = %+v, cursor %d", next, cursor)
	}
}

func TestEventsHonoursLevelAndLimit(t *testing.T) {
	isolate(t, 10)
	Eventf(LevelDebug, "c", "dbg")
	Eventf(LevelInfo, "c", "inf")
	Eventf(LevelWarn, "c", "wrn")
	Eventf(LevelError, "c", "err")

	warn, _ := Events(0, LevelWarn, 0)
	if len(warn) != 2 || warn[0].Message != "wrn" || warn[1].Message != "err" {
		t.Errorf("level filter = %+v", warn)
	}
	limited, _ := Events(0, LevelDebug, 2)
	if len(limited) != 2 || limited[1].Message != "err" {
		t.Errorf("a limit should return the newest matching events, got %+v", limited)
	}
}

// Raising the console level must not lose history: the Logs section is exactly the place a user
// goes to see what a quieter console hid.
func TestRaisedConsoleLevelStillRecordsInTheRing(t *testing.T) {
	buf := isolate(t, 10)
	SetLevel(LevelError)
	Eventf(LevelInfo, "quiet", "hidden from the console")
	Eventf(LevelError, "loud", "shown")

	if strings.Contains(buf.String(), "hidden") {
		t.Errorf("an info event was printed at error level: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "shown") {
		t.Errorf("an error event was not printed: %q", buf.String())
	}
	evs := Snapshot()
	if len(evs) != 2 {
		t.Fatalf("the ring kept %d events, want both", len(evs))
	}
	if evs[0].Code != "quiet" || evs[0].LevelID != "info" {
		t.Errorf("the hidden event was not recorded faithfully: %+v", evs[0])
	}
}

func TestPrintfKeepsTheOriginalBehaviour(t *testing.T) {
	buf := isolate(t, 10)
	Printf("engine listening on %s", "127.0.0.1:1080")
	if got := strings.TrimSpace(buf.String()); got != "engine listening on 127.0.0.1:1080" {
		t.Errorf("Printf output = %q", got)
	}
	evs := Snapshot()
	if len(evs) != 1 || evs[0].Level != LevelInfo || evs[0].Message != "engine listening on 127.0.0.1:1080" {
		t.Errorf("Printf should be one Info event, got %+v", evs)
	}
}

func TestEventCodesAppearInThePrintedLine(t *testing.T) {
	buf := isolate(t, 10)
	EventDetail(LevelWarn, "ttl.apply", "applying TTL 65", "Set-NetIPv4Protocol -DefaultHopLimit 65")
	out := buf.String()
	if !strings.Contains(out, "[ttl.apply] applying TTL 65") {
		t.Errorf("the printed line should carry the code, got %q", out)
	}
	evs := Snapshot()
	if len(evs) != 1 || evs[0].Detail == "" {
		t.Errorf("the detail must be kept apart from the message, got %+v", evs)
	}
}

func TestSearchFiltersAndOrdersNewestFirst(t *testing.T) {
	isolate(t, 10)
	Eventf(LevelInfo, "engine.dial", "dialing")
	Eventf(LevelWarn, "ttl.apply", "applying TTL")
	EventDetail(LevelError, "ttl.apply", "failed", "access is denied for C:\\Users\\alex")

	byCode := Search(Filter{Code: "ttl.apply"}, 0)
	if len(byCode) != 2 {
		t.Fatalf("code filter = %d events, want 2", len(byCode))
	}
	if byCode[0].Message != "failed" {
		t.Errorf("search must be newest first, got %q first", byCode[0].Message)
	}
	if got := Search(Filter{Min: LevelError}, 0); len(got) != 1 || got[0].Code != "ttl.apply" {
		t.Errorf("level filter = %+v", got)
	}
	// The query matches message and detail, case-insensitively.
	if got := Search(Filter{Query: "ACCESS IS DENIED"}, 0); len(got) != 1 {
		t.Errorf("detail should be searchable, got %+v", got)
	}
	if got := Search(Filter{Query: "dialing"}, 0); len(got) != 1 || got[0].Code != "engine.dial" {
		t.Errorf("message search = %+v", got)
	}
	if got := Search(Filter{Code: "nope"}, 0); len(got) != 0 {
		t.Errorf("an unmatched filter must return nothing, got %+v", got)
	}
	if got := Search(Filter{}, 1); len(got) != 1 || got[0].Message != "failed" {
		t.Errorf("limit should keep the newest, got %+v", got)
	}
}

func TestParseLevelAndLevelNames(t *testing.T) {
	cases := map[string]Level{"debug": LevelDebug, "INFO": LevelInfo, "": LevelInfo, "warn": LevelWarn, "warning": LevelWarn, " Error ": LevelError}
	for in, want := range cases {
		if got, ok := ParseLevel(in); !ok || got != want {
			t.Errorf("ParseLevel(%q) = %v,%v want %v,true", in, got, ok, want)
		}
	}
	if _, ok := ParseLevel("loud"); ok {
		t.Error("a typo must be reported, not silently defaulted")
	}
	for l, want := range map[Level]string{LevelDebug: "debug", LevelInfo: "info", LevelWarn: "warn", LevelError: "error"} {
		if l.String() != want {
			t.Errorf("Level(%d).String() = %q, want %q", int(l), l.String(), want)
		}
	}
}

func TestZeroRingCapacityDisablesHistoryWithoutBreakingOutput(t *testing.T) {
	buf := isolate(t, 0)
	Eventf(LevelInfo, "c", "still printed")
	if len(Snapshot()) != 0 {
		t.Error("a zero-capacity ring must keep nothing")
	}
	if !strings.Contains(buf.String(), "still printed") {
		t.Error("disabling history must not disable console output")
	}
}

func TestRotatingFileKeepsBoundedHistoryAndWholeRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "net-merge.log")
	rf, err := OpenRotating(path, 50, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()

	const lines = 20
	for i := 0; i < lines; i++ {
		if _, err := fmt.Fprintf(rf, "line-%04d\n", i); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	// With a 50-byte cap and 10-byte records, three files of five records are retained.
	var kept []string
	for _, p := range []string{path, path + ".1", path + ".2"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("expected rotated file %s: %v", p, err)
		}
		if len(b) > 50 {
			t.Errorf("%s is %d bytes, over the cap", filepath.Base(p), len(b))
		}
		for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if line != "" {
				kept = append(kept, line)
			}
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Error("more files were kept than maxFiles allows")
	}
	if len(kept) != 15 {
		t.Fatalf("kept %d records, want 15: %v", len(kept), kept)
	}
	// Records are whole and the order matches the writes, across file boundaries.
	sorted := append([]string{}, kept...)
	sort.Strings(sorted)
	for i, line := range sorted {
		want := fmt.Sprintf("line-%04d", 5+i)
		if line != want {
			t.Errorf("record %d = %q, want %q (the last 15 writes, none split or lost)", i, line, want)
		}
	}
}

func TestRotationDisabledWithoutACap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "n.log")
	rf, err := OpenRotating(path, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	for i := 0; i < 100; i++ {
		if _, err := fmt.Fprintf(rf, "line-%04d\n", i); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Error("rotation happened with maxBytes disabled")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(strings.TrimRight(string(b), "\n"), "\n")) != 100 {
		t.Errorf("rotating writer lost records: %d lines", len(strings.Split(strings.TrimRight(string(b), "\n"), "\n")))
	}
}

func TestClosedRotatingFileReportsTheError(t *testing.T) {
	rf, err := OpenRotating(filepath.Join(t.TempDir(), "x.log"), 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := rf.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rf.Write([]byte("after close\n")); err == nil {
		t.Error("writing to a closed log file must report an error, not drop the record silently")
	}
}

func TestCountAndSinceStart(t *testing.T) {
	isolate(t, 5)
	if Count() != 0 {
		t.Fatalf("a fresh ring starts at 0, got %d", Count())
	}
	Eventf(LevelInfo, "c", "one")
	if Count() != 1 {
		t.Errorf("Count = %d, want 1", Count())
	}
	if SinceStart() < 0 {
		t.Error("SinceStart must not be negative")
	}
}

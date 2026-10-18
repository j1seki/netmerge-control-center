// Package logx is net-merge's console/log-file output, shared by every package.
//
// It is deliberately dependency-free and small. Three things live here:
//
//   - The plain Printf the engine has always used. It keeps working exactly as before and
//     is treated as an Info-level event, so existing call sites need no changes.
//
//   - A bounded in-memory ring of structured events, so the Control Center's Logs section can
//     show what happened without a second logging service and without unbounded memory use.
//     Every event carries a monotonic sequence number, which is what lets the dashboard fetch
//     only what is new since its last poll instead of re-reading the whole buffer.
//
//   - A rotating file writer. A tray/dashboard process can run for weeks; one log file that
//     grows forever is a disk problem, and truncating on start (the old `-log` behaviour)
//     throws away the evidence a crash report needs. Rotation keeps both.
//
// Nothing here is allowed to block a caller meaningfully: the ring is fixed-size and the file
// write is a normal file write. A logging call that can fail a network operation would be a
// bug, so failures are dropped rather than propagated.
package logx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Level is how severe an event is. The zero value is Info so that an unconfigured logger
// behaves like the console output net-merge always had.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return fmt.Sprintf("level(%d)", int(l))
	}
}

// ParseLevel accepts the names shown in the Settings section. It is case-insensitive so a
// hand-edited config file with "INFO" is still usable, and it reports failure rather than
// silently choosing a level: a typo must not quietly hide errors.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, true
	case "info", "":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error":
		return LevelError, true
	default:
		return LevelInfo, false
	}
}

// Levels lists the levels the UI offers, in order.
func Levels() []Level { return []Level{LevelDebug, LevelInfo, LevelWarn, LevelError} }

// Event is one log record. Code is a stable, greppable identifier ("ttl.apply", "engine.dial")
// that the UI can filter on and that error documentation can refer to; Message is the part a
// person reads. Detail is optional extra text (a command line, an error) kept separate so the
// one-line display stays one line.
type Event struct {
	Seq     uint64    `json:"seq"`
	At      time.Time `json:"at"`
	Level   Level     `json:"level"`
	LevelID string    `json:"levelName"`
	Code    string    `json:"code,omitempty"`
	Message string    `json:"message"`
	Detail  string    `json:"detail,omitempty"`
}

type ring struct {
	mu  sync.Mutex
	buf []Event
	seq uint64 // number of events ever appended
	cap int
}

func (r *ring) append(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cap <= 0 {
		return
	}
	r.seq++
	e.Seq = r.seq
	if len(r.buf) == r.cap {
		copy(r.buf, r.buf[1:])
		r.buf[len(r.buf)-1] = e
		return
	}
	r.buf = append(r.buf, e)
}

// since returns up to limit events newer than seq, oldest first, plus the newest sequence
// number currently in the ring. The seq is returned even when nothing matches, because it is
// what a client stores as its cursor.
func (r *ring) since(seq uint64, minLevel Level, limit int) ([]Event, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, 0, min(limit, len(r.buf)))
	for _, e := range r.buf {
		if e.Seq > seq && e.Level >= minLevel {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, r.seq
}

// search returns the newest events matching a filter, newest first.
func (r *ring) search(f Filter, limit int) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Event
	for i := len(r.buf) - 1; i >= 0; i-- {
		e := r.buf[i]
		if f.matches(e) {
			out = append(out, e)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

func (r *ring) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.buf))
	copy(out, r.buf)
	return out
}

var (
	mu     sync.Mutex
	out    io.Writer = os.Stdout
	level            = LevelInfo
	events           = &ring{cap: DefaultRingCapacity}
)

// DefaultRingCapacity is how many events the in-memory history keeps. It is sized so a
// dashboard can show "what happened recently" (a few thousand records is well under a
// megabyte) without letting a long-running process grow without bound.
const DefaultRingCapacity = 2000

// SetOutput sends all further output to w (the -log file). It is the original API and is
// kept verbatim so existing callers do not change behaviour.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	out = w
}

// SetLevel sets the minimum level that is printed.
func SetLevel(l Level) {
	mu.Lock()
	defer mu.Unlock()
	level = l
}

// GetLevel returns the minimum level that is printed.
func GetLevel() Level {
	mu.Lock()
	defer mu.Unlock()
	return level
}

// SetRingCapacity resizes the in-memory history. A non-positive value disables it.
func SetRingCapacity(n int) {
	mu.Lock()
	defer mu.Unlock()
	events = &ring{cap: n}
}

// Printf is the original net-merge log call: console output at Info level. It is what the
// engine, tun and tray packages already use, and its formatting rules are unchanged.
func Printf(format string, a ...any) {
	emit(LevelInfo, "", fmt.Sprintf(format, a...), "")
}

// Eventf logs one structured event. Code is a stable identifier (see the package docs);
// prefer it over a one-off string so the UI filter and the troubleshooting guide can refer
// to it.
func Eventf(l Level, code, format string, a ...any) {
	emit(l, code, fmt.Sprintf(format, a...), "")
}

// EventDetail is Eventf with a second, optional text block (a command line, an error body).
func EventDetail(l Level, code, message, detail string) {
	emit(l, code, message, detail)
}

func emit(l Level, code, msg, detail string) {
	mu.Lock()
	w, min := out, level
	mu.Unlock()
	if l < min {
		// Still recorded: the ring is the "recent history" view and gets its own level
		// filter at read time, so raising the console level must not erase evidence.
		events.append(Event{At: time.Now(), Level: l, LevelID: l.String(), Code: code, Message: msg, Detail: detail})
		return
	}
	line := msg
	if code != "" {
		line = "[" + code + "] " + line
	}
	if w != nil {
		fmt.Fprintln(w, line)
	}
	events.append(Event{At: time.Now(), Level: l, LevelID: l.String(), Code: code, Message: msg, Detail: detail})
}

// Filter selects events for the Logs section. Zero values mean "no restriction".
type Filter struct {
	Min   Level
	Code  string // substring match, case-insensitive
	Query string // substring match over message+detail, case-insensitive
}

func (f Filter) matches(e Event) bool {
	if e.Level < f.Min {
		return false
	}
	if f.Code != "" && !strings.Contains(strings.ToLower(e.Code), strings.ToLower(f.Code)) {
		return false
	}
	if f.Query != "" {
		q := strings.ToLower(f.Query)
		if !strings.Contains(strings.ToLower(e.Message), q) && !strings.Contains(strings.ToLower(e.Detail), q) {
			return false
		}
	}
	return true
}

// Events returns events newer than seq (oldest first) plus the newest sequence number seen,
// which the caller stores as its cursor for the next call.
func Events(since uint64, min Level, limit int) ([]Event, uint64) {
	return events.since(since, min, limit)
}

// Search returns the newest events matching f, newest first.
func Search(f Filter, limit int) []Event {
	return events.search(f, limit)
}

// Snapshot returns every retained event, oldest first. It is what the diagnostic export
// serialises; Search is what an interactive view uses.
func Snapshot() []Event { return events.all() }

// Count is the number of events ever logged in this process, which is the sequence number.
func Count() uint64 {
	events.mu.Lock()
	defer events.mu.Unlock()
	return events.seq
}

// RotatingFile is a log sink that renames the file aside once it passes maxBytes, keeping at
// most maxFiles old files (path.1 is the most recent). Rotation happens at a write boundary,
// so a single record is never split across files.
type RotatingFile struct {
	path     string
	maxBytes int64
	maxFiles int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenRotating opens (creating if needed) a rotating log file. maxBytes <= 0 disables
// rotation, which is only sensible for a short-lived process; maxFiles < 1 is treated as 1.
func OpenRotating(path string, maxBytes int64, maxFiles int) (*RotatingFile, error) {
	if maxFiles < 1 {
		maxFiles = 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	r := &RotatingFile{path: path, maxBytes: maxBytes, maxFiles: maxFiles}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil {
		r.size = st.Size()
	}
	r.f = f
	return r, nil
}

// Path is the file this writer appends to.
func (r *RotatingFile) Path() string { return r.path }

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.maxBytes > 0 && r.size+int64(len(p)) > r.maxBytes && r.size > 0 {
		if err := r.rotateLocked(); err != nil {
			// A failed rotation must not lose the record: keep appending to the open file
			// and let size grow rather than silently dropping output.
			r.size += int64(len(p))
			return r.f.Write(p)
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotateLocked() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	// path.(maxFiles-1) is the oldest; drop it, then shift the rest up.
	oldest := r.shiftPath(r.maxFiles)
	_ = os.Remove(oldest)
	for i := r.maxFiles - 1; i >= 1; i-- {
		src, dst := r.shiftPath(i), r.shiftPath(i+1)
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, dst); err != nil {
				return err
			}
		}
	}
	if err := os.Rename(r.path, r.shiftPath(1)); err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

func (r *RotatingFile) shiftPath(n int) string {
	if n <= 0 {
		return r.path
	}
	return fmt.Sprintf("%s.%d", r.path, n)
}

// Close closes the underlying file. Further writes fail with os.ErrClosed.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// SinceStart returns how long this process has been running. It is used by the diagnostic
// report so a reader can tell "this happened 3s ago" from "this has been true since boot".
var started = time.Now()

func SinceStart() time.Duration { return time.Since(started) }

// SortEventsByTime is exported for the report builder, which merges in-memory events with
// on-disk history and needs one deterministic order.
func SortEventsByTime(evs []Event) {
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].At.Before(evs[j].At) })
}

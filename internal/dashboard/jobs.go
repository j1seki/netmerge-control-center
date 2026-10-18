package dashboard

// Background jobs. A diagnostics run shells out to PowerShell and tracert and can take a
// minute; an export renders and redacts the whole document. Neither may run inside an HTTP
// request, because a request that takes a minute is indistinguishable from a hung dashboard and
// a browser will happily time it out while the work continues invisibly.
//
// So the pattern is: a request starts a job and returns its id at once; the UI polls the job.
// Jobs are kept in a bounded ordered store, they are cancellable, and they are cancelled when
// the server closes so no work outlives the window that asked for it.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"net-merge/internal/diag"
	"net-merge/internal/diagreport"
)

// Job statuses.
const (
	JobRunning   = "running"
	JobDone      = "done"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
)

// exportResult is what an export job produces: the two rendered artifacts plus what was
// redacted. Entries is the placeholder-to-value mapping; it is deliberately not part of either
// artifact and must never be written to a file.
type exportResult struct {
	BaseName string                     `json:"baseName"`
	Text     string                     `json:"text"`
	JSON     string                     `json:"json"`
	Counts   diagreport.RedactionCounts `json:"redactionCounts"`
	Entries  []diagreport.Entry         `json:"redactionEntries"`
	Saved    []string                   `json:"saved,omitempty"`
}

// job is one background operation.
type job struct {
	mu       sync.Mutex
	id       string
	kind     string // "diag" | "export"
	status   string
	started  time.Time
	finished time.Time
	progress string
	err      string
	diag     *diag.RunResult
	export   *exportResult
	cancel   context.CancelFunc
}

// view renders the job for the API. The heavy payloads are included only once the job is
// terminal, so a poll while running stays small.
type jobView struct {
	ID       string        `json:"id"`
	Kind     string        `json:"kind"`
	Status   string        `json:"status"`
	Started  time.Time     `json:"started"`
	Finished time.Time     `json:"finished,omitempty"`
	Progress string        `json:"progress,omitempty"`
	Error    string        `json:"error,omitempty"`
	Diag     *diagView     `json:"diag,omitempty"`
	Export   *exportResult `json:"export,omitempty"`
}

type diagView struct {
	Result diag.RunResult `json:"result"`
}

func (j *job) view() jobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	v := jobView{
		ID: j.id, Kind: j.kind, Status: j.status, Started: j.started,
		Finished: j.finished, Progress: j.progress, Error: j.err,
	}
	if j.diag != nil {
		v.Diag = &diagView{Result: *j.diag}
	}
	if j.export != nil {
		e := *j.export
		v.Export = &e
	}
	return v
}

func (j *job) setProgress(p string) {
	j.mu.Lock()
	j.progress = p
	j.mu.Unlock()
}

// diagResult returns the completed diagnostics result, or nil.
func (j *job) diagResult() *diag.RunResult {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.diag
}

// exportCopy returns a copy of the export payload so a caller never mutates the job's own copy
// without going through the job's methods.
func (j *job) exportCopy() *exportResult {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.export == nil {
		return nil
	}
	e := *j.export
	return &e
}

func (j *job) markSaved(paths []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.export != nil {
		j.export.Saved = paths
	}
}

// jobStore keeps jobs in start order and drops the oldest finished one when it is full. A
// running job is never evicted.
type jobStore struct {
	mu    sync.Mutex
	order []*job
	max   int
	seq   int
}

func newJobStore(max int) *jobStore { return &jobStore{max: max} }

func (s *jobStore) add(kind string, cancel context.CancelFunc) *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	j := &job{
		id:      fmt.Sprintf("%s-%d", kind, s.seq),
		kind:    kind,
		status:  JobRunning,
		started: time.Now(),
		cancel:  cancel,
	}
	s.order = append(s.order, j)
	// Evict from the front, skipping running jobs.
	for len(s.order) > s.max {
		victim := -1
		for i, c := range s.order {
			c.mu.Lock()
			done := c.status != JobRunning
			c.mu.Unlock()
			if done {
				victim = i
				break
			}
		}
		if victim < 0 {
			break
		}
		s.order = append(s.order[:victim], s.order[victim+1:]...)
	}
	return j
}

func (s *jobStore) get(id string) (*job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.order {
		if j.id == id {
			return j, true
		}
	}
	return nil, false
}

// list returns the newest jobs first, which is the order a UI wants.
func (s *jobStore) list(kind string, limit int) []jobView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]jobView, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		if kind != "" && s.order[i].kind != kind {
			continue
		}
		out = append(out, s.order[i].view())
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// lastDone returns the most recent finished diagnostics run, which is what an export includes
// when the user has not asked for a fresh one.
func (s *jobStore) lastDone(kind string) *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.order) - 1; i >= 0; i-- {
		j := s.order[i]
		if j.kind != kind {
			continue
		}
		j.mu.Lock()
		done := j.status == JobDone
		j.mu.Unlock()
		if done {
			return j
		}
	}
	return nil
}

// cancelAll is called when the server closes so no background work outlives it.
func (s *jobStore) cancelAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.order {
		j.mu.Lock()
		c := j.cancel
		j.mu.Unlock()
		if c != nil {
			c()
		}
	}
}

// startJob runs fn in the background under the server's context. The job's own context is
// cancelled by Close (via the store) or by the cancel endpoint.
func (s *Server) startJob(kind string, fn func(ctx context.Context) (any, error)) *job {
	ctx, cancel := context.WithCancel(s.baseCtx)
	j := s.jobs.add(kind, cancel)
	go func() {
		defer cancel()
		v, err := fn(ctx)
		j.mu.Lock()
		defer j.mu.Unlock()
		j.finished = s.now()
		switch {
		case ctx.Err() != nil:
			// Cancellation is decided by the context, not by the error: a run that returns a
			// partial result (which is what a cancelled diagnostics run does) is still cancelled.
			j.status = JobCancelled
			j.err = "cancelled"
		case err != nil:
			j.status = JobFailed
			j.err = err.Error()
		default:
			j.status = JobDone
			switch r := v.(type) {
			case diag.RunResult:
				rr := r
				j.diag = &rr
			case *diag.RunResult:
				j.diag = r
			case exportResult:
				e := r
				j.export = &e
			case *exportResult:
				j.export = r
			}
		}
	}()
	return j
}

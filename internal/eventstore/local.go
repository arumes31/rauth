package eventstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"rauth/internal/requestevent"
)

// LocalStats serves administrator statistics for a standalone server that has
// no cluster event store. It is process-local and bounded: per-minute traffic
// cells cover 24h, half-hour cells cover 7d, and the most recent decisions
// back rankings, free-form filters and decision history. Record never does I/O.
type LocalStats struct {
	mu       sync.Mutex
	started  time.Time
	now      func() time.Time
	minutes  []localBucket
	halves   []localBucket
	ring     []requestevent.Event
	start    int
	count    int
	seq      uint64
	overflow uint64
	latest   time.Time
}

const (
	localMinuteSlots   = 24*60 + 2
	localHalfHourSlots = 7*48 + 2
	localRecentLimit   = 20000
	localCellLimit     = 96
	localOtherCountry  = "other"
	localActions       = 6
	// Records older than this behind the newest one mean the clock stepped back.
	localClockStep = 2 * time.Minute
)

// localCellBound is the exact per-bucket cell bound: localCellLimit distinct
// cells plus one folded "other" country cell per action and latency bucket
// (including unknown latency).
func localCellBound() int { return localCellLimit + localActions*(len(latencyEdges)+2) }

type localCell struct {
	action  string
	country string
	bucket  int
}

type localBucket struct {
	at    time.Time
	cells map[localCell]uint64
}

func NewLocalStats() *LocalStats {
	return newLocalStats(time.Now)
}

func newLocalStats(now func() time.Time) *LocalStats {
	return &LocalStats{started: now().UTC(), now: now, minutes: make([]localBucket, localMinuteSlots), halves: make([]localBucket, localHalfHourSlots), ring: make([]requestevent.Event, localRecentLimit)}
}

// Record is the request middleware sink. The event is cleaned with the same
// projection the durable store accepts.
func (l *LocalStats) Record(raw requestevent.Event) {
	if l == nil {
		return
	}
	e := requestevent.Decision(raw)
	if e.Time.IsZero() {
		e.Time = l.now()
	}
	e.Time = e.Time.UTC()
	switch e.Action {
	case "authenticated", "bypass", "login_required", "rate_limited", "blocked", "error":
	default:
		e.Action = "error"
	}
	if e.Country == "" {
		e.Country = "unknown"
	}
	cell := localCell{e.Action, e.Country, latencyBucket(e.ProcessingMicros)}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.latest.IsZero() && e.Time.Before(l.latest.Add(-localClockStep)) {
		// The wall clock stepped back. Drop buckets from the abandoned future so
		// aggregates never mix them with, or lose, current traffic.
		l.discardAfter(e.Time)
	}
	if e.Time.After(l.latest) || e.Time.Before(l.latest.Add(-localClockStep)) {
		l.latest = e.Time
	}
	l.add(l.minutes, e.Time.Truncate(time.Minute), time.Minute, cell)
	l.add(l.halves, e.Time.Truncate(30*time.Minute), 30*time.Minute, cell)
	l.seq++
	e.ID = l.seq
	e.ReceivedAt = e.Time
	if l.count < len(l.ring) {
		l.ring[(l.start+l.count)%len(l.ring)] = e
		l.count++
	} else {
		l.ring[l.start] = e
		l.start = (l.start + 1) % len(l.ring)
	}
}

func (l *LocalStats) discardAfter(at time.Time) {
	for _, slots := range [][]localBucket{l.minutes, l.halves} {
		for i := range slots {
			if slots[i].at.After(at) {
				slots[i] = localBucket{}
			}
		}
	}
	kept := l.recentLocked()[:0]
	for _, e := range l.recentLocked() {
		if !e.Time.After(at) {
			kept = append(kept, e)
		}
	}
	l.start, l.count = 0, len(kept)
	copy(l.ring, kept)
}

func (l *LocalStats) add(slots []localBucket, at time.Time, step time.Duration, cell localCell) {
	slot := &slots[int((at.Unix()/int64(step/time.Second))%int64(len(slots)))]
	if !slot.at.Equal(at) {
		slot.at = at
		slot.cells = map[localCell]uint64{}
	}
	if _, ok := slot.cells[cell]; !ok && cell.country != localOtherCountry {
		if distinct := len(slot.cells) - l.foldedCells(slot); distinct >= localCellLimit {
			// Keep memory bounded under many distinct countries. Totals,
			// actions and latency stay exact; see localCellBound.
			cell.country = localOtherCountry
			l.overflow++
		}
	}
	slot.cells[cell]++
}

func (l *LocalStats) foldedCells(slot *localBucket) int {
	n := 0
	for c := range slot.cells {
		if c.country == localOtherCountry {
			n++
		}
	}
	return n
}

func (q StatsQuery) rawFiltered() bool {
	return q.Domain != "" || q.Source != "" || q.URL != "" || q.Reason != ""
}

func (q StatsQuery) matches(e requestevent.Event, start, end time.Time) bool {
	return !e.Time.Before(start) && !e.Time.After(end) && (q.Country == "" || e.Country == q.Country) && (q.Action == "" || e.Action == q.Action) && (q.Domain == "" || eventDomain(e.URL) == q.Domain) && (q.Source == "" || e.Source == q.Source) && (q.URL == "" || e.URL == q.URL) && (q.Reason == "" || e.Reason == q.Reason)
}

func (l *LocalStats) Statistics(ctx context.Context, q StatsQuery) (StatsSnapshot, error) {
	if l == nil {
		return StatsSnapshot{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return StatsSnapshot{}, ErrUnavailable
	}
	now := l.now().UTC()
	start, duration, err := q.Window(now)
	if err != nil {
		return StatsSnapshot{}, err
	}
	step := time.Minute
	if duration > time.Hour {
		step = 5 * time.Minute
	}
	if duration > 24*time.Hour {
		step = 30 * time.Minute
	}
	// Report the oldest data the bounded storage can still serve.
	retained := l.started
	if oldest := now.Truncate(30 * time.Minute).Add(-(localHalfHourSlots - 2) * 30 * time.Minute); oldest.After(retained) {
		retained = oldest
	}
	out := StatsSnapshot{GeneratedAt: now, Start: start, End: now, BucketSeconds: int64(step / time.Second), Query: q, Actions: []Dimension{}, Countries: []Dimension{}, Timeline: []TrafficPoint{}, Top: map[string][]Dimension{}, Nodes: []NodeSample{}, RetainedSince: &retained,
		Coverage: "this server process only (standalone mode, no cluster event store); history resets on restart"}
	actionCounts, countryCounts := map[string]uint64{}, map[string]uint64{}
	timeline := map[trafficKey]uint64{}
	histogram := make([]uint64, len(latencyEdges)+1)
	byTime := map[time.Time][]uint64{}
	addCell := func(at time.Time, c localCell, n uint64) {
		at = at.Truncate(step)
		out.Total += n
		actionCounts[c.action] += n
		countryCounts[c.country] += n
		timeline[trafficKey{at, c.action}] += n
		if c.bucket < 0 {
			out.Latency.Unknown += n
			return
		}
		histogram[c.bucket] += n
		if byTime[at] == nil {
			byTime[at] = make([]uint64, len(histogram))
		}
		byTime[at][c.bucket] += n
		out.Latency.Samples += n
	}
	l.mu.Lock()
	recent := l.recentLocked()
	if q.Node == "" && !q.rawFiltered() {
		slots, cutoff := l.minutes, start
		if step == 30*time.Minute {
			slots, cutoff = l.halves, start.Truncate(step)
			// Half-hour cells cannot be split; report the boundary counted.
			out.Start = cutoff
		}
		for _, b := range slots {
			if b.cells == nil || b.at.Before(cutoff) || b.at.After(now) {
				continue
			}
			for c, n := range b.cells {
				if (q.Country == "" || c.country == q.Country) && (q.Action == "" || c.action == q.Action) {
					addCell(b.at, c, n)
				}
			}
		}
	}
	l.mu.Unlock()
	// Raw text filters can only be answered from retained recent decisions.
	if q.Node == "" && q.rawFiltered() {
		if len(recent) == localRecentLimit && recent[0].Time.After(retained) {
			retained = recent[0].Time
		}
		for _, e := range recent {
			if q.matches(e, start, now) {
				addCell(e.Time, localCell{e.Action, e.Country, latencyBucket(e.ProcessingMicros)}, 1)
			}
		}
		out.Coverage += "; text filters use the most recent 20,000 decisions"
	}
	out.Actions = dimensions(actionCounts)
	out.Countries = dimensions(countryCounts)
	for key, count := range timeline {
		out.Timeline = append(out.Timeline, TrafficPoint{key.at, key.action, count})
	}
	sort.Slice(out.Timeline, func(i, j int) bool {
		if out.Timeline[i].Time.Equal(out.Timeline[j].Time) {
			return out.Timeline[i].Action < out.Timeline[j].Action
		}
		return out.Timeline[i].Time.Before(out.Timeline[j].Time)
	})
	for at, h := range byTime {
		out.LatencyTimeline = append(out.LatencyTimeline, LatencyPoint{at, quantile(h, .5), quantile(h, .95), quantile(h, .99)})
	}
	sort.Slice(out.LatencyTimeline, func(i, j int) bool { return out.LatencyTimeline[i].Time.Before(out.LatencyTimeline[j].Time) })
	out.Latency.Approximate = true
	out.Latency.P50 = quantile(histogram, .50)
	out.Latency.P95 = quantile(histogram, .95)
	out.Latency.P99 = quantile(histogram, .99)
	out.TopScope = "Up to 20,000 most recent matching decisions in the selected window (this process)"
	if q.Node == "" {
		out.Top = localTop(recent, q, start, now)
	}
	return out, nil
}

func localTop(recent []requestevent.Event, q StatsQuery, start, end time.Time) map[string][]Dimension {
	counts := map[string]map[string]uint64{"urls": {}, "domains": {}, "ips": {}, "reasons": {}, "feeds": {}}
	for _, e := range recent {
		if !q.matches(e, start, end) {
			continue
		}
		counts["urls"][e.URL]++
		counts["domains"][eventDomain(e.URL)]++
		counts["ips"][e.Source]++
		counts["reasons"][e.Reason]++
		counts["feeds"][e.FeedID]++
	}
	out := map[string][]Dimension{}
	for name, m := range counts {
		if len(m) == 0 {
			continue
		}
		d := dimensions(m)
		if len(d) > 20 {
			d = d[:20]
		}
		out[name] = d
	}
	return out
}

// recentLocked copies retained decisions oldest first. Caller holds l.mu.
func (l *LocalStats) recentLocked() []requestevent.Event {
	out := make([]requestevent.Event, 0, l.count)
	for i := 0; i < l.count; i++ {
		out = append(out, l.ring[(l.start+i)%len(l.ring)])
	}
	return out
}

// Decisions pages newest first with the same keyset contract as the store.
func (l *LocalStats) Decisions(ctx context.Context, q StatsQuery) ([]requestevent.Event, error) {
	if l == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrUnavailable
	}
	now := l.now().UTC()
	start, _, err := q.Window(now)
	if err != nil {
		return nil, ErrInvalid
	}
	out := []requestevent.Event{}
	if q.Node != "" {
		return out, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := l.count - 1; i >= 0 && len(out) < 100; i-- {
		e := l.ring[(l.start+i)%len(l.ring)]
		if (q.Before == 0 || e.ID < q.Before) && q.matches(e, start, now) {
			out = append(out, e)
		}
	}
	return out, nil
}

// Diagnostics need durable per-node captures, which standalone mode lacks.
func (l *LocalStats) Diagnostics(context.Context, string) (Diagnostics, error) {
	return Diagnostics{}, ErrUnavailable
}

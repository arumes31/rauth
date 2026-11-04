package eventstore

import (
	"context"
	"testing"
	"time"

	"rauth/internal/requestevent"
)

type localClock struct{ t time.Time }

func (c *localClock) now() time.Time { return c.t }

func localEvent(at time.Time, action, country, url, source string, us int64) requestevent.Event {
	return requestevent.Event{Time: at, Action: action, Country: country, URL: url, Source: source, ProcessingMicros: us, Status: 200}
}

func TestLocalStatsAggregatesWindowAndFilters(t *testing.T) {
	clock := &localClock{time.Date(2026, 11, 4, 12, 30, 20, 0, time.UTC)}
	l := newLocalStats(clock.now)
	now := clock.t
	l.Record(localEvent(now.Add(-2*time.Hour), "authenticated", "AT", "https://old.example/x", "198.51.100.9", 500))
	l.Record(localEvent(now.Add(-10*time.Minute), "authenticated", "AT", "https://a.example/p?secret=1", "198.51.100.1", 2000))
	l.Record(localEvent(now.Add(-5*time.Minute), "blocked", "US", "https://b.example/q", "203.0.113.7", 50000))
	l.Record(localEvent(now.Add(-time.Minute), "authenticated", "AT", "https://a.example/p", "198.51.100.1", 0))

	s, err := l.Statistics(context.Background(), StatsQuery{Range: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Total != 3 || s.RetainedSince == nil || s.BucketSeconds != 60 {
		t.Fatalf("total=%d retained=%v bucket=%d", s.Total, s.RetainedSince, s.BucketSeconds)
	}
	if s.Actions[0] != (Dimension{"authenticated", 2}) || s.Countries[0] != (Dimension{"AT", 2}) {
		t.Fatalf("actions=%v countries=%v", s.Actions, s.Countries)
	}
	if s.Latency.Samples != 2 || s.Latency.Unknown != 1 || s.Latency.P99 == nil {
		t.Fatalf("latency=%+v", s.Latency)
	}
	if got := s.Top["domains"]; len(got) != 2 || got[0] != (Dimension{"a.example", 2}) {
		t.Fatalf("top domains=%v", got)
	}
	if got := s.Top["urls"]; got[0].Key != "https://a.example/p" {
		t.Fatalf("query string leaked or url missing: %v", got)
	}

	s, err = l.Statistics(context.Background(), StatsQuery{Range: "1h", Action: "blocked"})
	if err != nil || s.Total != 1 {
		t.Fatalf("action filter total=%d err=%v", s.Total, err)
	}
	s, err = l.Statistics(context.Background(), StatsQuery{Range: "1h", Domain: "a.example"})
	if err != nil || s.Total != 2 {
		t.Fatalf("domain filter total=%d err=%v", s.Total, err)
	}
	s, err = l.Statistics(context.Background(), StatsQuery{Range: "24h"})
	if err != nil || s.Total != 4 || s.BucketSeconds != 300 {
		t.Fatalf("24h total=%d bucket=%d err=%v", s.Total, s.BucketSeconds, err)
	}
	s, err = l.Statistics(context.Background(), StatsQuery{Range: "7d"})
	if err != nil || s.Total != 4 || s.BucketSeconds != 1800 {
		t.Fatalf("7d total=%d bucket=%d err=%v", s.Total, s.BucketSeconds, err)
	}
	if _, err = l.Statistics(context.Background(), StatsQuery{Range: "2h"}); err != ErrInvalid {
		t.Fatalf("invalid range err=%v", err)
	}
}

func TestLocalStatsExpiresOldBuckets(t *testing.T) {
	clock := &localClock{time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	l := newLocalStats(clock.now)
	l.Record(localEvent(clock.t, "authenticated", "AT", "https://a.example/", "198.51.100.1", 10))
	clock.t = clock.t.Add(25 * time.Hour)
	// A new event lands in a slot the day-old minute shared modulo the ring.
	l.Record(localEvent(clock.t.Add(-2*time.Hour), "blocked", "AT", "https://a.example/", "198.51.100.1", 10))
	s, err := l.Statistics(context.Background(), StatsQuery{Range: "24h"})
	if err != nil || s.Total != 1 || s.Actions[0].Key != "blocked" {
		t.Fatalf("total=%d actions=%v err=%v", s.Total, s.Actions, err)
	}
	s, err = l.Statistics(context.Background(), StatsQuery{Range: "7d"})
	if err != nil || s.Total != 2 {
		t.Fatalf("7d total=%d err=%v", s.Total, err)
	}
}

func TestLocalStatsDecisionsPageNewestFirst(t *testing.T) {
	clock := &localClock{time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	l := newLocalStats(clock.now)
	for i := 0; i < 150; i++ {
		l.Record(localEvent(clock.t.Add(-time.Duration(150-i)*time.Second), "authenticated", "AT", "https://a.example/", "198.51.100.1", 10))
	}
	page, err := l.Decisions(context.Background(), StatsQuery{Range: "1h"})
	if err != nil || len(page) != 100 || page[0].ID != 150 || page[99].ID != 51 {
		t.Fatalf("len=%d err=%v", len(page), err)
	}
	page, err = l.Decisions(context.Background(), StatsQuery{Range: "1h", Before: page[99].ID})
	if err != nil || len(page) != 50 || page[0].ID != 50 {
		t.Fatalf("second page len=%d err=%v", len(page), err)
	}
	page, err = l.Decisions(context.Background(), StatsQuery{Range: "1h", Node: "8f6f9ef4-6a3c-4b51-9d0f-1f5d7e2f9a10"})
	if err != nil || len(page) != 0 {
		t.Fatalf("node filter len=%d err=%v", len(page), err)
	}
}

func TestLocalStatsBoundsCellsAcrossActionsAndLatency(t *testing.T) {
	clock := &localClock{time.Date(2026, 11, 4, 12, 0, 30, 0, time.UTC)}
	l := newLocalStats(clock.now)
	actions := []string{"authenticated", "bypass", "login_required", "rate_limited", "blocked", "error"}
	latencies := []int64{0, 1, 2000, 5000, 20000, 50000, 200000, 500000, 2000000, 5000000, 20000000, 40000000, 90000000, 200000000, 700000000}
	total := 0
	for i := 0; i < 26*26; i++ {
		c := string(rune('A'+i/26)) + string(rune('A'+i%26))
		for j, a := range actions {
			l.Record(localEvent(clock.t, a, c, "", "198.51.100.1", latencies[(i+j)%len(latencies)]))
			total++
		}
	}
	slot := l.minutes[int((clock.t.Truncate(time.Minute).Unix()/60)%int64(len(l.minutes)))]
	if n := len(slot.cells); n > localCellBound() {
		t.Fatalf("cells=%d bound=%d", n, localCellBound())
	}
	s, err := l.Statistics(context.Background(), StatsQuery{Range: "5m"})
	if err != nil || s.Total != uint64(total) || s.Latency.Samples+s.Latency.Unknown != uint64(total) {
		t.Fatalf("total=%d latency=%+v err=%v", s.Total, s.Latency, err)
	}
	if s, err = l.Statistics(context.Background(), StatsQuery{Range: "5m", Country: "other"}); err != nil || s.Total == 0 {
		t.Fatalf("other filter total=%d err=%v", s.Total, err)
	}
}

func TestLocalStatsClockStepBackDiscardsAbandonedFuture(t *testing.T) {
	clock := &localClock{time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	l := newLocalStats(clock.now)
	l.Record(localEvent(clock.t, "blocked", "AT", "https://a.example/", "198.51.100.1", 10))
	clock.t = clock.t.Add(-26 * time.Hour)
	l.Record(localEvent(clock.t, "authenticated", "AT", "https://a.example/", "198.51.100.1", 10))
	clock.t = clock.t.Add(26*time.Hour + time.Minute)
	s, err := l.Statistics(context.Background(), StatsQuery{Range: "24h"})
	if err != nil || s.Total != 0 {
		t.Fatalf("future bucket survived: total=%d err=%v", s.Total, err)
	}
	page, _ := l.Decisions(context.Background(), StatsQuery{Range: "7d"})
	if len(page) != 1 || page[0].Action != "authenticated" {
		t.Fatalf("decisions=%v", page)
	}
}

func TestLocalStatsSevenDayStartAndRetention(t *testing.T) {
	clock := &localClock{time.Date(2026, 11, 4, 12, 17, 0, 0, time.UTC)}
	l := newLocalStats(clock.now)
	clock.t = clock.t.Add(10 * 24 * time.Hour)
	s, err := l.Statistics(context.Background(), StatsQuery{Range: "7d"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Start.Minute()%30 != 0 || s.Start.After(clock.t.Add(-7*24*time.Hour)) {
		t.Fatalf("start=%v", s.Start)
	}
	if s.RetainedSince == nil || clock.t.Sub(*s.RetainedSince) > 7*24*time.Hour+30*time.Minute {
		t.Fatalf("retained_since=%v", s.RetainedSince)
	}
}

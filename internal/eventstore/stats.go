package eventstore

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"math"
	"net/netip"
	"net/url"
	"rauth/internal/requestevent"
	"sort"
	"strconv"
	"strings"
	"time"
)

// StatsQuery accepts exact bounded dimensions. It never becomes SQL syntax.
// High-cardinality drilldowns use the normalized time index and a read deadline.
type StatsQuery struct {
	Range   string `json:"range"`
	Node    string `json:"node,omitempty"`
	Country string `json:"country,omitempty"`
	Action  string `json:"action,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Source  string `json:"source,omitempty"`
	URL     string `json:"url,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Before  uint64 `json:"before,omitempty"`
}

func (q StatsQuery) Window(now time.Time) (time.Time, time.Duration, error) {
	duration := map[string]time.Duration{"5m": 5 * time.Minute, "1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}[q.Range]
	if duration == 0 || q.Node != "" && !requestevent.ValidID(q.Node) || q.Before > math.MaxInt64 {
		return time.Time{}, 0, ErrInvalid
	}
	if q.Country != "" && q.Country != "unknown" && q.Country != "other" && (len(q.Country) != 2 || q.Country[0] < 'A' || q.Country[0] > 'Z' || q.Country[1] < 'A' || q.Country[1] > 'Z') {
		return time.Time{}, 0, ErrInvalid
	}
	if q.Action != "" {
		switch q.Action {
		case "authenticated", "bypass", "login_required", "rate_limited", "blocked", "error":
		default:
			return time.Time{}, 0, ErrInvalid
		}
	}
	if q.Domain != "" {
		if ip, err := netip.ParseAddr(q.Domain); err == nil {
			if ip.Zone() != "" {
				return time.Time{}, 0, ErrInvalid
			}
		} else {
			u, err := url.Parse("https://" + q.Domain)
			if err != nil || u.Hostname() != q.Domain || u.Host != q.Domain || u.Path != "" || len(q.Domain) > 253 || strings.ContainsAny(q.Domain, "?#@ ") {
				return time.Time{}, 0, ErrInvalid
			}
		}
	}
	if q.Source != "" {
		ip, err := netip.ParseAddr(q.Source)
		if q.Source != "unknown" && (err != nil || ip.Zone() != "" || ip.Unmap().String() != q.Source) {
			return time.Time{}, 0, ErrInvalid
		}
	}
	if q.URL != "" && requestevent.Decision(requestevent.Event{URL: q.URL}).URL != q.URL {
		return time.Time{}, 0, ErrInvalid
	}
	if len(q.Reason) > 64 || strings.ContainsAny(q.Reason, "\r\n\x00") {
		return time.Time{}, 0, ErrInvalid
	}
	return now.UTC().Truncate(time.Minute).Add(-duration), duration, nil
}

type Dimension struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}
type TrafficPoint struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Count  uint64    `json:"count"`
}
type Latency struct {
	Samples     uint64   `json:"samples"`
	Unknown     uint64   `json:"unknown"`
	P50         *float64 `json:"p50_ms"`
	P95         *float64 `json:"p95_ms"`
	P99         *float64 `json:"p99_ms"`
	Approximate bool     `json:"approximate"`
}
type NodeSample struct {
	NodeID          string                      `json:"node_id"`
	NodeName        string                      `json:"node_name"`
	Time            time.Time                   `json:"time"`
	ReceivedAt      time.Time                   `json:"received_at"`
	Snapshot        requestevent.MetricSnapshot `json:"snapshot"`
	Stale           bool                        `json:"stale"`
	IntervalCovered bool                        `json:"interval_covered"`
	Rates           map[string]float64          `json:"rates"`
}
type LatencyPoint struct {
	Time time.Time `json:"time"`
	P50  *float64  `json:"p50_ms"`
	P95  *float64  `json:"p95_ms"`
	P99  *float64  `json:"p99_ms"`
}
type StatsSnapshot struct {
	TopScope        string                 `json:"top_scope"`
	TopUnavailable  bool                   `json:"top_unavailable"`
	LatencyTimeline []LatencyPoint         `json:"latency_timeline"`
	GeneratedAt     time.Time              `json:"generated_at"`
	Start           time.Time              `json:"start"`
	End             time.Time              `json:"end"`
	BucketSeconds   int64                  `json:"bucket_seconds"`
	Query           StatsQuery             `json:"query"`
	Total           uint64                 `json:"total"`
	Actions         []Dimension            `json:"actions"`
	Countries       []Dimension            `json:"countries"`
	Timeline        []TrafficPoint         `json:"timeline"`
	Latency         Latency                `json:"latency"`
	Top             map[string][]Dimension `json:"top"`
	Nodes           []NodeSample           `json:"nodes"`
	RetainedSince   *time.Time             `json:"retained_since"`
	Expired         uint64                 `json:"expired"`
	LossMarkers     uint64                 `json:"loss_markers"`
	Coverage        string                 `json:"coverage"`
}

func (s *Store) Statistics(parent context.Context, q StatsQuery) (StatsSnapshot, error) {
	now := s.now().UTC()
	start, duration, err := q.Window(now)
	if err != nil {
		return StatsSnapshot{}, err
	}
	ctx, cancel := context.WithTimeout(parent, ReadTimeout)
	defer cancel()
	tx, err := s.stats.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return StatsSnapshot{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	step := time.Minute
	if duration > time.Hour {
		step = 5 * time.Minute
	}
	if duration > 24*time.Hour {
		step = 30 * time.Minute
	}
	out := StatsSnapshot{GeneratedAt: now, Start: start, End: now, BucketSeconds: int64(step / time.Second), Query: q, Actions: []Dimension{}, Countries: []Dimension{}, Timeline: []TrafficPoint{}, Top: map[string][]Dimension{}, Nodes: []NodeSample{}, Coverage: "retained history; node samples have a separate byte cap and at most 24h retention; missing observations are not zero"}
	args := []any{s.options.ClusterID, start, now, q.Node, q.Country, q.Action}
	condition := `cluster_id=$1 AND occurred_at>=$2 AND occurred_at<=$3 AND ($4='' OR node_id::text=$4) AND ($5='' OR country=$5) AND ($6='' OR action=$6)`
	table := "request_events"
	trafficCondition := strings.ReplaceAll(condition, "occurred_at", "minute")
	trafficTable := "event_traffic_minute"
	countExpr := "sum(decisions)::bigint"
	timeColumn := "minute"
	if q.Domain != "" || q.Source != "" || q.URL != "" || q.Reason != "" {
		trafficTable = table
		trafficCondition = condition + ` AND kind='decision' AND ($7='' OR domain=$7) AND ($8='' OR source=$8) AND ($9='' OR url=$9) AND ($10='' OR reason=$10)`
		args = append(args, q.Domain, q.Source, q.URL, q.Reason)
		countExpr = "count(*)"
		timeColumn = "occurred_at"
	}
	// These independent reads share the same repeatable-read snapshot. Pipeline
	// them so a remote primary does not spend the read budget on serial RTTs.
	batch := &pgx.Batch{}
	batch.Queue(`SELECT (SELECT min(occurred_at) FROM request_events WHERE cluster_id=$1),expired_count,(SELECT count(*) FROM request_events WHERE cluster_id=$1 AND kind='gap' AND occurred_at>=$2) FROM event_ledgers WHERE cluster_id=$1`, s.options.ClusterID, start)
	batch.Queue(`SELECT date_bin(make_interval(secs=>`+intString(out.BucketSeconds)+`),`+timeColumn+`,timestamptz '2000-01-01'),action,country,latency_bucket,`+countExpr+` FROM `+trafficTable+` WHERE `+trafficCondition+` GROUP BY 1,2,3,4 ORDER BY 1`, args...)
	batch.Queue(nodeSamplesSQL, s.options.ClusterID, now.Add(-7*24*time.Hour), q.Node)
	results := tx.SendBatch(ctx, batch)
	defer func() { _ = results.Close() }()
	if results.QueryRow().Scan(&out.RetainedSince, &out.Expired, &out.LossMarkers) != nil {
		return StatsSnapshot{}, ErrUnavailable
	}
	rows, err := results.Query()
	if err != nil {
		return StatsSnapshot{}, ErrUnavailable
	}
	actionCounts, countryCounts := map[string]uint64{}, map[string]uint64{}
	timeline := map[trafficKey]uint64{}
	histogram := make([]uint64, len(latencyEdges)+1)
	byTime := map[time.Time][]uint64{}
	for rows.Next() {
		var at time.Time
		var action, country string
		var bucket int
		var count uint64
		if rows.Scan(&at, &action, &country, &bucket, &count) != nil {
			rows.Close()
			return StatsSnapshot{}, ErrUnavailable
		}
		out.Total += count
		actionCounts[action] += count
		countryCounts[country] += count
		timeline[trafficKey{at, action}] += count
		if bucket < 0 {
			out.Latency.Unknown += count
		} else if bucket < len(histogram) {
			histogram[bucket] += count
			if byTime[at] == nil {
				byTime[at] = make([]uint64, len(histogram))
			}
			byTime[at][bucket] += count
			out.Latency.Samples += count
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return StatsSnapshot{}, ErrUnavailable
	}
	rows, err = results.Query()
	if err != nil {
		return StatsSnapshot{}, ErrUnavailable
	}
	out.Nodes, err = readNodeSamples(rows, now)
	closeErr := results.Close()
	if err != nil || closeErr != nil {
		return StatsSnapshot{}, ErrUnavailable
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
	// GROUPING SETS scans the filtered raw range once for the six top-N panels.
	if len(args) == 6 {
		args = append(args, q.Domain, q.Source, q.URL, q.Reason)
	}
	rawCondition := condition + ` AND kind='decision' AND ($7='' OR domain=$7) AND ($8='' OR source=$8) AND ($9='' OR url=$9) AND ($10='' OR reason=$10)`
	out.TopScope = "Up to 20,000 most recent matching decisions in the selected window"
	// Optional rankings keep a separate statement deadline and recoverable
	// savepoint without imposing a network round trip for each control command.
	out.Top, out.TopUnavailable, err = queryOptionalTop(ctx, tx, args, rawCondition)
	if err != nil {
		return StatsSnapshot{}, ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return StatsSnapshot{}, ErrUnavailable
	}
	return out, nil
}

type trafficKey struct {
	at     time.Time
	action string
}

func dimensions(counts map[string]uint64) []Dimension {
	out := make([]Dimension, 0, len(counts))
	for key, count := range counts {
		out = append(out, Dimension{key, count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	return out
}
func intString(n int64) string { return strconv.FormatInt(n, 10) }
func quantile(counts []uint64, p float64) *float64 {
	var total uint64
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		return nil
	}
	target := uint64(math.Ceil(float64(total) * p))
	var cumulative uint64
	for i, n := range counts {
		cumulative += n
		if cumulative >= target {
			edge := latencyEdges[len(latencyEdges)-1]
			if i < len(latencyEdges) {
				edge = latencyEdges[i]
			}
			v := float64(edge) / 1000
			return &v
		}
	}
	return nil
}

const nodeSamplesSQL = `WITH nodes AS (SELECT DISTINCT node_id FROM event_node_samples WHERE cluster_id=$1 AND NOT is_diagnostic AND occurred_at>=$2 AND ($3='' OR node_id::text=$3) ORDER BY node_id LIMIT 64) SELECT n.node_id::text,s.node_name,s.occurred_at,s.received_at,s.snapshot FROM nodes n CROSS JOIN LATERAL(SELECT * FROM event_node_samples e WHERE e.cluster_id=$1 AND e.node_id=n.node_id AND NOT is_diagnostic ORDER BY occurred_at DESC,seq DESC LIMIT 2) s ORDER BY n.node_id,s.occurred_at DESC`

func readNodeSamples(rows pgx.Rows, now time.Time) ([]NodeSample, error) {
	defer rows.Close()
	out := []NodeSample{}
	last := ""
	for rows.Next() {
		var sample NodeSample
		var raw []byte
		if err := rows.Scan(&sample.NodeID, &sample.NodeName, &sample.Time, &sample.ReceivedAt, &raw); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &sample.Snapshot) != nil {
			return nil, ErrUnavailable
		}
		if sample.NodeID != last {
			sample.Stale = now.Sub(sample.Time) > 15*time.Second || sample.Time.After(now.Add(time.Second))
			sample.Rates = map[string]float64{}
			out = append(out, sample)
			last = sample.NodeID
			continue
		}
		latest := &out[len(out)-1]
		interval := latest.Time.Sub(sample.Time).Seconds()
		latest.IntervalCovered = interval >= 1 && interval <= 15 && latest.Snapshot.InstanceID == sample.Snapshot.InstanceID && !sample.Snapshot.Partial && !latest.Snapshot.Partial
		if latest.IntervalCovered {
			previous := map[string]float64{}
			for _, point := range sample.Snapshot.Points {
				previous[point.Name] = point.Value
			}
			for _, point := range latest.Snapshot.Points {
				old, ok := previous[point.Name]
				if ok && strings.HasSuffix(point.Name, "_total") && point.Value >= old {
					latest.Rates[point.Name] = (point.Value - old) / interval
				}
			}
		}
	}
	return out, rows.Err()
}

// Decisions is keyset-paginated and uses a dedicated history pool, never auth.
func (s *Store) Decisions(parent context.Context, q StatsQuery) ([]requestevent.Event, error) {
	now := s.now().UTC()
	start, _, err := q.Window(now)
	if err != nil || q.Before > math.MaxInt64 {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, ReadTimeout)
	defer cancel()
	if q.Before > math.MaxInt64 {
		return nil, ErrInvalid
	}
	rows, err := s.history.Query(ctx, `SELECT seq,received_at,payload FROM request_events WHERE cluster_id=$1 AND kind='decision' AND occurred_at>=$2 AND occurred_at<=$3 AND ($4='' OR node_id::text=$4) AND ($5='' OR country=$5) AND ($6='' OR action=$6) AND ($7='' OR domain=$7) AND ($8='' OR source=$8) AND ($9='' OR url=$9) AND ($10='' OR reason=$10) AND ($11::bigint=0 OR seq<$11) ORDER BY seq DESC LIMIT 100`, s.options.ClusterID, start, now, q.Node, q.Country, q.Action, q.Domain, q.Source, q.URL, q.Reason, int64(q.Before))
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	out := []requestevent.Event{}
	for rows.Next() {
		var e requestevent.Event
		var raw []byte
		if rows.Scan(&e.ID, &e.ReceivedAt, &raw) != nil {
			return nil, ErrUnavailable
		}
		id, received := e.ID, e.ReceivedAt
		if json.Unmarshal(raw, &e) != nil {
			return nil, ErrUnavailable
		}
		e.ID = id
		e.ReceivedAt = received
		out = append(out, e)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}

type Diagnostics struct {
	NodeID   string                        `json:"node_id"`
	NodeName string                        `json:"node_name"`
	Time     time.Time                     `json:"time"`
	Complete bool                          `json:"complete"`
	Parts    []requestevent.MetricSnapshot `json:"parts"`
}

func (s *Store) Diagnostics(parent context.Context, node string) (Diagnostics, error) {
	if !requestevent.ValidID(node) {
		return Diagnostics{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, ReadTimeout)
	defer cancel()
	out := Diagnostics{NodeID: node, Parts: []requestevent.MetricSnapshot{}}
	rows, err := s.stats.Query(ctx, `WITH latest AS (SELECT snapshot->>'capture_id' AS capture FROM event_node_samples WHERE cluster_id=$1 AND node_id=$2 AND is_diagnostic ORDER BY occurred_at DESC,seq DESC LIMIT 1) SELECT node_name,occurred_at,snapshot FROM event_node_samples WHERE cluster_id=$1 AND node_id=$2 AND is_diagnostic AND snapshot->>'capture_id'=(SELECT capture FROM latest) ORDER BY seq LIMIT 8`, s.options.ClusterID, node)
	if err != nil {
		return out, ErrUnavailable
	}
	defer rows.Close()
	seen := map[int]bool{}
	expected := 0
	for rows.Next() {
		var snapshot requestevent.MetricSnapshot
		var raw []byte
		if rows.Scan(&out.NodeName, &out.Time, &raw) != nil || json.Unmarshal(raw, &snapshot) != nil {
			return Diagnostics{}, ErrUnavailable
		}
		expected = snapshot.Parts
		seen[snapshot.Part] = true
		out.Parts = append(out.Parts, snapshot)
	}
	if rows.Err() != nil {
		return Diagnostics{}, ErrUnavailable
	}
	out.Complete = expected > 0 && len(seen) == expected
	return out, nil
}

func queryOptionalTop(ctx context.Context, tx pgx.Tx, args []any, condition string) (map[string][]Dimension, bool, error) {
	batch := &pgx.Batch{}
	batch.Queue("SAVEPOINT optional_top")
	batch.Queue("SET LOCAL statement_timeout='250ms'")
	batch.Queue(`WITH candidates AS MATERIALIZED(SELECT url,domain,source,reason,feed_id FROM request_events WHERE `+condition+` ORDER BY occurred_at DESC,seq DESC LIMIT 20000),grouped AS(SELECT CASE WHEN grouping(url)=0 THEN 'urls' WHEN grouping(domain)=0 THEN 'domains' WHEN grouping(source)=0 THEN 'ips' WHEN grouping(reason)=0 THEN 'reasons' ELSE 'feeds' END AS dimension,COALESCE(url,domain,source,reason,feed_id,'') AS key,count(*)::bigint AS n FROM candidates GROUP BY GROUPING SETS((url),(domain),(source),(reason),(feed_id))),ranked AS(SELECT *,row_number() OVER(PARTITION BY dimension ORDER BY n DESC,key) AS rank FROM grouped) SELECT dimension,key,n FROM ranked WHERE rank<=20 ORDER BY dimension,n DESC,key`, args...)
	results := tx.SendBatch(ctx, batch)
	defer func() { _ = results.Close() }()
	if _, err := results.Exec(); err != nil {
		return nil, false, err
	}
	if _, err := results.Exec(); err != nil {
		return nil, false, err
	}
	rows, err := results.Query()
	out := map[string][]Dimension{}
	if err == nil {
		for rows.Next() {
			var dimension string
			var d Dimension
			if err = rows.Scan(&dimension, &d.Key, &d.Count); err != nil {
				break
			}
			out[dimension] = append(out[dimension], d)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
	}
	closeErr := results.Close()
	unavailable := err != nil || closeErr != nil
	cleanup := "SET LOCAL statement_timeout='1500ms'; RELEASE SAVEPOINT optional_top"
	if unavailable {
		out = map[string][]Dimension{}
		cleanup = "ROLLBACK TO SAVEPOINT optional_top; " + cleanup
	}
	if _, err = tx.Exec(ctx, cleanup); err != nil {
		return nil, false, err
	}
	return out, unavailable, nil
}

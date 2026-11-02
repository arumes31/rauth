// Package nodetelemetry captures bounded process metrics without network calls
// or authentication queries. Per-process identity makes counter resets explicit.
package nodetelemetry

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"math"
	"rauth/internal/requestevent"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Collector struct {
	gatherer prometheus.Gatherer
	instance string
	started  time.Time
	revision string
}

func New(gatherer prometheus.Gatherer) *Collector {
	if gatherer == nil {
		gatherer = prometheus.DefaultGatherer
	}
	revision := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				revision = setting.Value
			}
		}
	}
	return &Collector{gatherer: gatherer, instance: uuid.NewString(), started: time.Now().UTC(), revision: revision}
}

var essential = map[string]bool{
	"rauth_second_factor_total": true,
	"rauth_login_success_total": true, "rauth_login_failed_total": true, "rauth_rate_limit_hits_total": true, "rauth_active_sessions": true, "rauth_audit_logs_total": true, "rauth_geoip_lookups_total": true, "rauth_geoip_db_build_timestamp": true, "rauth_recovery_code_used_total": true, "rauth_auth_bypass_total": true,
	"rauth_forward_auth_decisions_total": true, "rauth_forward_auth_processing_seconds": true,
	"process_cpu_seconds_total": true, "process_resident_memory_bytes": true, "process_start_time_seconds": true, "process_open_fds": true, "process_max_fds": true,
}

func (c *Collector) Capture() requestevent.MetricSnapshot {
	out := requestevent.MetricSnapshot{Schema: 1, InstanceID: c.instance, StartedAt: c.started, GoVersion: runtime.Version(), BuildRevision: c.revision, Points: []requestevent.MetricPoint{}}
	families, err := c.gatherer.Gather()
	out.Partial = err != nil
	appendPoint := func(name string, value float64) {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || len(out.Points) >= 64 {
			out.Partial = true
			return
		}
		out.Points = append(out.Points, requestevent.MetricPoint{Name: name, Value: value})
	}
	for _, family := range families {
		name := family.GetName()
		if !essential[name] {
			continue
		}
		var total, sum, count float64
		for _, metric := range family.Metric {
			switch family.GetType() {
			case dto.MetricType_COUNTER:
				total += metric.GetCounter().GetValue()
			case dto.MetricType_GAUGE:
				total += metric.GetGauge().GetValue()
			case dto.MetricType_HISTOGRAM:
				sum += metric.GetHistogram().GetSampleSum()
				count += float64(metric.GetHistogram().GetSampleCount())
			}
		}
		if family.GetType() == dto.MetricType_HISTOGRAM {
			appendPoint(name+"_sum", sum)
			appendPoint(name+"_count", count)
		} else {
			appendPoint(name, total)
		}
		if name == "process_start_time_seconds" && total > 0 && total < float64(time.Now().Unix()+120) {
			whole, fraction := math.Modf(total)
			out.StartedAt = time.Unix(int64(whole), int64(fraction*1e9)).UTC()
		}
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	for name, value := range map[string]float64{"go_goroutines": float64(runtime.NumGoroutine()), "go_heap_alloc_bytes": float64(memory.HeapAlloc), "go_heap_inuse_bytes": float64(memory.HeapInuse), "go_heap_sys_bytes": float64(memory.HeapSys), "go_gc_cycles_total": float64(memory.NumGC), "go_gc_pause_seconds_total": float64(memory.PauseTotalNs) / 1e9, "go_gomaxprocs": float64(runtime.GOMAXPROCS(0))} {
		appendPoint(name, value)
	}
	sort.Slice(out.Points, func(i, j int) bool { return out.Points[i].Name < out.Points[j].Name })
	return out
}

// Diagnostics includes locally registered RAuth, Go and process numeric series,
// preserving only fixed operational labels. It cannot carry arbitrary label keys
// or text values. Bounded chunks use one capture identity for completeness checks.
func (c *Collector) Diagnostics() []requestevent.MetricSnapshot {
	families, err := c.gatherer.Gather()
	capture := uuid.NewString()
	partial := err != nil
	points := []requestevent.MetricPoint{}
	add := func(name string, value float64, labels map[string]string) {
		point := requestevent.MetricPoint{Name: name, Value: value, Labels: labels}
		probe := requestevent.MetricSnapshot{Schema: 1, InstanceID: c.instance, StartedAt: c.started, Diagnostics: true, CaptureID: capture, Parts: 1, Points: []requestevent.MetricPoint{point}}
		if requestevent.ValidateMetrics(&probe, time.Now()) != nil {
			partial = true
			return
		}
		points = append(points, point)
	}
	for _, family := range families {
		name := family.GetName()
		if !strings.HasPrefix(name, "go_") && !strings.HasPrefix(name, "process_") && !strings.HasPrefix(name, "rauth_") && !strings.HasPrefix(name, "promhttp_") {
			partial = true
			continue
		}
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			extra := func(key, value string) map[string]string {
				out := map[string]string{}
				for k, v := range labels {
					out[k] = v
				}
				out[key] = value
				return out
			}
			switch family.GetType() {
			case dto.MetricType_COUNTER:
				add(name, metric.GetCounter().GetValue(), labels)
			case dto.MetricType_GAUGE:
				add(name, metric.GetGauge().GetValue(), labels)
			case dto.MetricType_UNTYPED:
				add(name, metric.GetUntyped().GetValue(), labels)
			case dto.MetricType_SUMMARY:
				summary := metric.GetSummary()
				add(name+"_sum", summary.GetSampleSum(), labels)
				add(name+"_count", float64(summary.GetSampleCount()), labels)
				for _, q := range summary.Quantile {
					add(name, q.GetValue(), extra("quantile", strconv.FormatFloat(q.GetQuantile(), 'g', -1, 64)))
				}
			case dto.MetricType_HISTOGRAM:
				h := metric.GetHistogram()
				add(name+"_sum", h.GetSampleSum(), labels)
				add(name+"_count", float64(h.GetSampleCount()), labels)
				for _, b := range h.Bucket {
					add(name+"_bucket", float64(b.GetCumulativeCount()), extra("le", strconv.FormatFloat(b.GetUpperBound(), 'g', -1, 64)))
				}
			default:
				partial = true
			}
		}
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].Name == points[j].Name {
			a, _ := json.Marshal(points[i].Labels)
			b, _ := json.Marshal(points[j].Labels)
			return string(a) < string(b)
		}
		return points[i].Name < points[j].Name
	})
	out := []requestevent.MetricSnapshot{}
	batch := requestevent.MetricSnapshot{Schema: 1, InstanceID: c.instance, StartedAt: c.started, GoVersion: runtime.Version(), BuildRevision: c.revision, Diagnostics: true, CaptureID: capture, Parts: 8, Points: []requestevent.MetricPoint{}}
	for _, point := range points {
		probe := batch.Clone()
		probe.Points = append(probe.Points, point)
		if requestevent.ValidateMetrics(&probe, time.Now()) != nil {
			if len(out) == 7 {
				partial = true
				break
			}
			out = append(out, batch)
			batch.Points = []requestevent.MetricPoint{}
		}
		batch.Points = append(batch.Points, point)
	}
	if len(batch.Points) > 0 || len(out) == 0 {
		out = append(out, batch)
	}
	for i := range out {
		out[i].Parts = len(out)
		out[i].Part = i
		out[i].Partial = partial
	}
	return out
}

package metrics

import (
	"encoding/json"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/version"
)

// When updating this struct, please make sure to update the relevant exporting functions
type Stats struct {
	EventCount             *counter.Counter `json:"EventCount"`
	EventsFiltered         *counter.Counter `json:"EventsFiltered"`
	EventsFilteredLast     time.Time
	NetCapCount            *counter.Counter `json:"NetCapCount"` // network capture events
	BPFLogsCount           *counter.Counter `json:"BPFLogsCount"`
	ErrorCount             *counter.Counter `json:"ErrorCount"`
	LostEvCount            *counter.Counter `json:"LostEvCount"`
	LostWrCount            *counter.Counter `json:"LostWrCount"`
	LostNtCapCount         *counter.Counter `json:"LostNtCapCount"` // lost network capture events
	LostBPFLogsCount       *counter.Counter `json:"LostBPFLogsCount"`
	DecodeIn               *counter.Counter `json:"DecodeIn"`
	DecodeInLast           time.Time
	DecodeOut              *counter.Counter `json:"DecodeOut"`
	DecodeOutLast          time.Time
	DecodeFiltered         *counter.Counter `json:"DecodeFiltered"`
	DecodeFilteredLast     time.Time
	QueueIn                *counter.Counter `json:"QueueIn"`
	QueueInLast            time.Time
	QueueOut               *counter.Counter `json:"QueueOut"`
	QueueOutLast           time.Time
	SortIn                 *counter.Counter `json:"SortIn"`
	SortInLast             time.Time
	SortOut                *counter.Counter `json:"SortOut"`
	SortOutLast            time.Time
	ProcessIn              *counter.Counter `json:"ProcessIn"`
	ProcessInLast          time.Time
	ProcessOut             *counter.Counter `json:"ProcessOut"`
	ProcessOutLast         time.Time
	ProcessFiltered        *counter.Counter `json:"ProcessFiltered"`
	ProcessFilteredLast    time.Time
	EnrichContainerIn      *counter.Counter `json:"EnrichContainerIn"`
	EnrichContainerInLast  time.Time
	EnrichContainerOut     *counter.Counter `json:"EnrichContainerOut"`
	EnrichContainerOutLast time.Time
	DeriveIn               *counter.Counter `json:"DeriveIn"`
	DeriveInLast           time.Time
	DeriveOut              *counter.Counter `json:"DeriveOut"`
	DeriveOutLast          time.Time
	EngineIn               *counter.Counter `json:"EngineIn"`
	EngineInLast           time.Time
	EngineOut              *counter.Counter `json:"EngineOut"`
	EngineOutLast          time.Time
	EngineFiltered         *counter.Counter `json:"EngineFiltered"`
	EngineFilteredLast     time.Time
	SinkIn                 *counter.Counter `json:"SinkIn"`
	SinkInLast             time.Time
	SinkOut                *counter.Counter `json:"SinkOut"`
	SinkOutLast            time.Time
	SinkFiltered           *counter.Counter `json:"SinkFiltered"`
	SinkFilteredLast       time.Time
	// NOTE: BPFPerfEventSubmit* metrics are periodically collected from the 'events_stats'
	// BPF map, while userspace metrics are continuously updated within the application
	// based on varying logic. Due to differences in data sources and collection timing,
	// the two sets of metrics are not directly synchronized. As a result, the total event
	// counts fetched from 'events_stats' may not align with those reported by userspace metrics.
	// Each metric set is designed to provide distinct insights and should be analyzed
	// independently, without direct comparison.
	BPFPerfEventSubmitAttemptsCount *EventCollector `json:"BPFPerfEventSubmitAttemptsCount,omitempty"`
	BPFPerfEventSubmitFailuresCount *EventCollector `json:"BPFPerfEventSubmitFailuresCount,omitempty"`
}

func NewStats() *Stats {
	stats := &Stats{
		EventCount:         counter.NewCounter(0),
		EventsFiltered:     counter.NewCounter(0),
		NetCapCount:        counter.NewCounter(0),
		BPFLogsCount:       counter.NewCounter(0),
		ErrorCount:         counter.NewCounter(0),
		LostEvCount:        counter.NewCounter(0),
		LostWrCount:        counter.NewCounter(0),
		LostNtCapCount:     counter.NewCounter(0),
		LostBPFLogsCount:   counter.NewCounter(0),
		DecodeIn:           counter.NewCounter(0),
		DecodeOut:          counter.NewCounter(0),
		DecodeFiltered:     counter.NewCounter(0),
		QueueIn:            counter.NewCounter(0),
		QueueOut:           counter.NewCounter(0),
		SortIn:             counter.NewCounter(0),
		SortOut:            counter.NewCounter(0),
		ProcessIn:          counter.NewCounter(0),
		ProcessOut:         counter.NewCounter(0),
		ProcessFiltered:    counter.NewCounter(0),
		EnrichContainerIn:  counter.NewCounter(0),
		EnrichContainerOut: counter.NewCounter(0),
		DeriveIn:           counter.NewCounter(0),
		DeriveOut:          counter.NewCounter(0),
		EngineIn:           counter.NewCounter(0),
		EngineOut:          counter.NewCounter(0),
		EngineFiltered:     counter.NewCounter(0),
		SinkIn:             counter.NewCounter(0),
		SinkOut:            counter.NewCounter(0),
		SinkFiltered:       counter.NewCounter(0),
	}

	if version.MetricsBuild() {
		stats.BPFPerfEventSubmitAttemptsCount = NewEventCollector(
			"Event submit attempts",
			prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "tracee_ebpf",
					Name:      "bpf_perf_event_submit_attempts",
					Help:      "calls to submit to the event perf buffer",
				},
				[]string{"event_name"},
			),
		)
		stats.BPFPerfEventSubmitFailuresCount = NewEventCollector(
			"Event submit failures",
			prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "tracee_ebpf",
					Name:      "bpf_perf_event_submit_failures",
					Help:      "failed calls to submit to the event perf buffer",
				},
				[]string{"event_name"},
			),
		)
	}

	return stats
}

// Register Stats to prometheus metrics exporter
func (s *Stats) RegisterPrometheus() error {
	err := prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "events_total",
		Help:      "events collected by tracee-ebpf",
	}, func() float64 { return float64(s.EventCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "events_filtered",
		Help:      "events filtered by tracee-ebpf in userspace",
	}, func() float64 { return float64(s.EventsFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "events_filtered_last",
		Help:      "last time event was filtered",
	}, func() float64 { return float64(s.EventsFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "network_capture_events_total",
		Help:      "network capture events collected by tracee-ebpf",
	}, func() float64 { return float64(s.NetCapCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "bpf_logs_total",
		Help:      "logs collected by tracee-ebpf during ebpf execution",
	}, func() float64 { return float64(s.BPFLogsCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	if version.MetricsBuild() {
		// Updated by countPerfEventSubmissions() goroutine
		err = prometheus.Register(s.BPFPerfEventSubmitAttemptsCount.GaugeVec())
		if err != nil {
			return errfmt.WrapError(err)
		}

		// Updated by countPerfEventSubmissions() goroutine
		err = prometheus.Register(s.BPFPerfEventSubmitFailuresCount.GaugeVec())
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "errors_total",
		Help:      "errors accumulated by tracee-ebpf",
	}, func() float64 { return float64(s.ErrorCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "lostevents_total",
		Help:      "events lost in the submission buffer",
	}, func() float64 { return float64(s.LostEvCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "write_lostevents_total",
		Help:      "events lost in the write buffer",
	}, func() float64 { return float64(s.LostWrCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "network_capture_lostevents_total",
		Help:      "network capture lost events in network capture buffer",
	}, func() float64 { return float64(s.LostNtCapCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// decode metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_in_total",
		Help:      "decoded in count",
	}, func() float64 { return float64(s.DecodeIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_in_last",
		Help:      "last time decoded event was received",
	}, func() float64 { return float64(s.DecodeInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_out_total",
		Help:      "total out count",
	}, func() float64 { return float64(s.DecodeOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_out_last",
		Help:      "last time decoded event was sent",
	}, func() float64 { return float64(s.DecodeOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_filtered_total",
		Help:      "decoded filtered count",
	}, func() float64 { return float64(s.DecodeFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_filtered_last",
		Help:      "last time decoded event was filtered",
	}, func() float64 { return float64(s.DecodeFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// queue metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "queue_in_total",
		Help:      "queue in count",
	}, func() float64 { return float64(s.QueueIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "queue_in_last",
		Help:      "last time event was queued",
	}, func() float64 { return float64(s.QueueInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "queue_out_total",
		Help:      "queue out count",
	}, func() float64 { return float64(s.QueueOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "queue_out_last",
		Help:      "last time event was dequeued",
	}, func() float64 { return float64(s.QueueOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// sort metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sort_in_total",
		Help:      "sort in count",
	}, func() float64 { return float64(s.SortIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sort_in_last",
		Help:      "last time event was sorted",
	}, func() float64 { return float64(s.SortInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sort_out_total",
		Help:      "sort out count",
	}, func() float64 { return float64(s.SortOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sort_out_last",
		Help:      "last time event was sorted",
	}, func() float64 { return float64(s.SortOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// process metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_in_total",
		Help:      "processed in count",
	}, func() float64 { return float64(s.ProcessIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_in_last",
		Help:      "last time processed event was received",
	}, func() float64 { return float64(s.ProcessInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_out_total",
		Help:      "processed out count",
	}, func() float64 { return float64(s.ProcessOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_out_last",
		Help:      "last time processed event was sent",
	}, func() float64 { return float64(s.ProcessOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_filtered_total",
		Help:      "processed filtered count",
	}, func() float64 { return float64(s.ProcessFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_filtered_last",
		Help:      "last time processed event was filtered",
	}, func() float64 { return float64(s.ProcessFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// enrich metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "enrich_in_total",
		Help:      "enriched in count",
	}, func() float64 { return float64(s.EnrichContainerIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "enrich_in_last",
		Help:      "last time enriched event was received",
	}, func() float64 { return float64(s.EnrichContainerInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "enrich_out_total",
		Help:      "enriched out events count",
	}, func() float64 { return float64(s.EnrichContainerOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "enrich_out_last",
		Help:      "last time enriched event was sent",
	}, func() float64 { return float64(s.EnrichContainerOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// derive metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "derive_in_total",
		Help:      "derive in count",
	}, func() float64 { return float64(s.DeriveIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "derive_in_last",
		Help:      "last time derive event was received",
	}, func() float64 { return float64(s.DeriveInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "derive_out_total",
		Help:      "derive out events count",
	}, func() float64 { return float64(s.DeriveOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "derive_out_last",
		Help:      "last time derive event was sent",
	}, func() float64 { return float64(s.DeriveOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// engine metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_in_total",
		Help:      "engine in count",
	}, func() float64 { return float64(s.EngineIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_in_last",
		Help:      "last time engine event was received",
	}, func() float64 { return float64(s.EngineInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_out_total",
		Help:      "total out count",
	}, func() float64 { return float64(s.EngineOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_out_last",
		Help:      "last time engine event was sent",
	}, func() float64 { return float64(s.EngineOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_filtered_total",
		Help:      "engine filtered count",
	}, func() float64 { return float64(s.EngineFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_filtered_last",
		Help:      "last time engine event was filtered",
	}, func() float64 { return float64(s.EngineFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// sink metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_in_total",
		Help:      "sink in count",
	}, func() float64 { return float64(s.SinkIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_in_last",
		Help:      "last time sink event was received",
	}, func() float64 { return float64(s.SinkInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_out_total",
		Help:      "total out count",
	}, func() float64 { return float64(s.SinkOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_out_last",
		Help:      "last time sink event was sent",
	}, func() float64 { return float64(s.SinkOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_filtered_total",
		Help:      "sink filtered count",
	}, func() float64 { return float64(s.SinkFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_filtered_last",
		Help:      "last time sink event was filtered",
	}, func() float64 { return float64(s.SinkFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	return errfmt.WrapError(err)
}

// JSON marshaler interface

func (s *Stats) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Stats Stats `json:"Stats"`
	}{Stats: *s})
}

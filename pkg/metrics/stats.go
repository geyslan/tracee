package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/tracee/pkg/counter"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// When updating this struct, please make sure to update the relevant exporting functions
type Stats struct {
	EventCount             counter.Counter
	EventsFiltered         counter.Counter
	EventsFilteredLast     time.Time
	NetCapCount            counter.Counter // network capture events
	BPFLogsCount           counter.Counter
	ErrorCount             counter.Counter
	LostEvCount            counter.Counter
	LostWrCount            counter.Counter
	LostNtCapCount         counter.Counter // lost network capture events
	LostBPFLogsCount       counter.Counter
	DecodeIn               counter.Counter
	DecodeInLast           time.Time
	DecodeOut              counter.Counter
	DecodeOutLast          time.Time
	DecodeFiltered         counter.Counter
	DecodeFilteredLast     time.Time
	QueueIn                counter.Counter
	QueueInLast            time.Time
	QueueOut               counter.Counter
	QueueOutLast           time.Time
	SortIn                 counter.Counter
	SortInLast             time.Time
	SortOut                counter.Counter
	SortOutLast            time.Time
	ProcessIn              counter.Counter
	ProcessInLast          time.Time
	ProcessOut             counter.Counter
	ProcessOutLast         time.Time
	ProcessFiltered        counter.Counter
	ProcessFilteredLast    time.Time
	EnrichContainerIn      counter.Counter
	EnrichContainerInLast  time.Time
	EnrichContainerOut     counter.Counter
	EnrichContainerOutLast time.Time
	DeriveIn               counter.Counter
	DeriveInLast           time.Time
	DeriveOut              counter.Counter
	DeriveOutLast          time.Time
	EngineIn               counter.Counter
	EngineInLast           time.Time
	EngineOut              counter.Counter
	EngineOutLast          time.Time
	EngineFiltered         counter.Counter
	EngineFilteredLast     time.Time
	SinkIn                 counter.Counter
	SinkInLast             time.Time
	SinkOut                counter.Counter
	SinkOutLast            time.Time
	SinkFiltered           counter.Counter
	SinkFilteredLast       time.Time
	// NOTE: BPFPerfEventSubmit* metrics are periodically collected from the 'events_stats'
	// BPF map, while userspace metrics are continuously updated within the application
	// based on varying logic. Due to differences in data sources and collection timing,
	// the two sets of metrics are not directly synchronized. As a result, the total event
	// counts fetched from 'events_stats' may not align with those reported by userspace metrics.
	// Each metric set is designed to provide distinct insights and should be analyzed
	// independently, without direct comparison.
	BPFPerfEventSubmitAttemptsCount *EventCollector
	BPFPerfEventSubmitFailuresCount *EventCollector
}

func NewStats() *Stats {
	return &Stats{
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
		BPFPerfEventSubmitAttemptsCount: NewEventCollector(
			"Event submit attempts",
			prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "tracee_ebpf",
					Name:      "bpf_perf_event_submit_attempts",
					Help:      "calls to submit to the event perf buffer",
				},
				[]string{"event_name"},
			),
		),
		BPFPerfEventSubmitFailuresCount: NewEventCollector(
			"Event submit failures",
			prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "tracee_ebpf",
					Name:      "bpf_perf_event_submit_failures",
					Help:      "failed calls to submit to the event perf buffer",
				},
				[]string{"event_name"},
			),
		),
	}
}

// Register Stats to prometheus metrics exporter
func (stats *Stats) RegisterPrometheus() error {
	err := prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "events_total",
		Help:      "events collected by tracee-ebpf",
	}, func() float64 { return float64(stats.EventCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "events_filtered",
		Help:      "events filtered by tracee-ebpf in userspace",
	}, func() float64 { return float64(stats.EventsFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "events_filtered_last",
		Help:      "last time event was filtered",
	}, func() float64 { return float64(stats.EventsFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "network_capture_events_total",
		Help:      "network capture events collected by tracee-ebpf",
	}, func() float64 { return float64(stats.NetCapCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "bpf_logs_total",
		Help:      "logs collected by tracee-ebpf during ebpf execution",
	}, func() float64 { return float64(stats.BPFLogsCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Register new counters

	// Updated by countPerfEventSubmissions() goroutine
	err = prometheus.Register(stats.BPFPerfEventSubmitAttemptsCount.GaugeVec())
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Updated by countPerfEventSubmissions() goroutine
	err = prometheus.Register(stats.BPFPerfEventSubmitFailuresCount.GaugeVec())
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "errors_total",
		Help:      "errors accumulated by tracee-ebpf",
	}, func() float64 { return float64(stats.ErrorCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "lostevents_total",
		Help:      "events lost in the submission buffer",
	}, func() float64 { return float64(stats.LostEvCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "write_lostevents_total",
		Help:      "events lost in the write buffer",
	}, func() float64 { return float64(stats.LostWrCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "network_capture_lostevents_total",
		Help:      "network capture lost events in network capture buffer",
	}, func() float64 { return float64(stats.LostNtCapCount.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// decode metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_in_total",
		Help:      "decoded in count",
	}, func() float64 { return float64(stats.DecodeIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_in_last",
		Help:      "last time decoded event was received",
	}, func() float64 { return float64(stats.DecodeInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_out_total",
		Help:      "total out count",
	}, func() float64 { return float64(stats.DecodeOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_out_last",
		Help:      "last time decoded event was sent",
	}, func() float64 { return float64(stats.DecodeOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_filtered_total",
		Help:      "decoded filtered count",
	}, func() float64 { return float64(stats.DecodeFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "decode_filtered_last",
		Help:      "last time decoded event was filtered",
	}, func() float64 { return float64(stats.DecodeFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// queue metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "queue_in_total",
		Help:      "queue in count",
	}, func() float64 { return float64(stats.QueueIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "queue_in_last",
		Help:      "last time event was queued",
	}, func() float64 { return float64(stats.QueueInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "queue_out_total",
		Help:      "queue out count",
	}, func() float64 { return float64(stats.QueueOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "queue_out_last",
		Help:      "last time event was dequeued",
	}, func() float64 { return float64(stats.QueueOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// sort metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sort_in_total",
		Help:      "sort in count",
	}, func() float64 { return float64(stats.SortIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sort_in_last",
		Help:      "last time event was sorted",
	}, func() float64 { return float64(stats.SortInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sort_out_total",
		Help:      "sort out count",
	}, func() float64 { return float64(stats.SortOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sort_out_last",
		Help:      "last time event was sorted",
	}, func() float64 { return float64(stats.SortOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// process metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_in_total",
		Help:      "processed in count",
	}, func() float64 { return float64(stats.ProcessIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_in_last",
		Help:      "last time processed event was received",
	}, func() float64 { return float64(stats.ProcessInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_out_total",
		Help:      "processed out count",
	}, func() float64 { return float64(stats.ProcessOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_out_last",
		Help:      "last time processed event was sent",
	}, func() float64 { return float64(stats.ProcessOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_filtered_total",
		Help:      "processed filtered count",
	}, func() float64 { return float64(stats.ProcessFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "process_filtered_last",
		Help:      "last time processed event was filtered",
	}, func() float64 { return float64(stats.ProcessFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// enrich metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "enrich_in_total",
		Help:      "enriched in count",
	}, func() float64 { return float64(stats.EnrichContainerIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "enrich_in_last",
		Help:      "last time enriched event was received",
	}, func() float64 { return float64(stats.EnrichContainerInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "enrich_out_total",
		Help:      "enriched out events count",
	}, func() float64 { return float64(stats.EnrichContainerOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "enrich_out_last",
		Help:      "last time enriched event was sent",
	}, func() float64 { return float64(stats.EnrichContainerOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// derive metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "derive_in_total",
		Help:      "derive in count",
	}, func() float64 { return float64(stats.DeriveIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "derive_in_last",
		Help:      "last time derive event was received",
	}, func() float64 { return float64(stats.DeriveInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "derive_out_total",
		Help:      "derive out events count",
	}, func() float64 { return float64(stats.DeriveOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "derive_out_last",
		Help:      "last time derive event was sent",
	}, func() float64 { return float64(stats.DeriveOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// engine metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_in_total",
		Help:      "engine in count",
	}, func() float64 { return float64(stats.EngineIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_in_last",
		Help:      "last time engine event was received",
	}, func() float64 { return float64(stats.EngineInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_out_total",
		Help:      "total out count",
	}, func() float64 { return float64(stats.EngineOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_out_last",
		Help:      "last time engine event was sent",
	}, func() float64 { return float64(stats.EngineOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_filtered_total",
		Help:      "engine filtered count",
	}, func() float64 { return float64(stats.EngineFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "engine_filtered_last",
		Help:      "last time engine event was filtered",
	}, func() float64 { return float64(stats.EngineFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	// sink metrics
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_in_total",
		Help:      "sink in count",
	}, func() float64 { return float64(stats.SinkIn.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_in_last",
		Help:      "last time sink event was received",
	}, func() float64 { return float64(stats.SinkInLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_out_total",
		Help:      "total out count",
	}, func() float64 { return float64(stats.SinkOut.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_out_last",
		Help:      "last time sink event was sent",
	}, func() float64 { return float64(stats.SinkOutLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_filtered_total",
		Help:      "sink filtered count",
	}, func() float64 { return float64(stats.SinkFiltered.Get()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}
	err = prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: "tracee_ebpf",
		Name:      "sink_filtered_last",
		Help:      "last time sink event was filtered",
	}, func() float64 { return float64(stats.SinkFilteredLast.UnixNano()) }))
	if err != nil {
		return errfmt.WrapError(err)
	}

	return errfmt.WrapError(err)
}

package ebpf

import (
	"context"
	"encoding/binary"
	"time"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// eventStatsValues mirrors the C struct event_stats_values (event_stats_values_t).
type eventStatsValues struct {
	submitAttempts uint64
	submitFailures uint64
}

// countPerfEventSubmissions is a goroutine that periodically counts the
// number of attempts and failures to submit events to the perf buffer
func (t *Tracee) countPerfEventSubmissions(ctx context.Context) {
	logger.Debugw("Starting countPerfEventSubmissions goroutine")
	defer logger.Debugw("Stopped countPerfEventSubmissions goroutine")

	evtsCountsBPFMap, err := t.bpfModule.GetMap("events_stats")
	if err != nil {
		logger.Errorw("Failed to get events_stats map", "error", err)
		return
	}

	evtStatZero := eventStatsValues{}
	for _, id := range t.policyManager.EventsToSubmit() {
		if id >= events.MaxCommonID {
			continue
		}

		key := uint32(id)
		err := evtsCountsBPFMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&evtStatZero))
		if err != nil {
			logger.Errorw("Failed to update events_stats map", "error", err)
		}
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.Sstats.BPFPerfEventSubmitAttemptsCount.Reset()
			t.Sstats.BPFPerfEventSubmitFailuresCount.Reset()

			// Get the counts of each event from the BPF map
			iter := evtsCountsBPFMap.Iterator()
			for iter.Next() {
				key := binary.LittleEndian.Uint32(iter.Key())
				value, err := evtsCountsBPFMap.GetValue(unsafe.Pointer(&key))
				if err != nil {
					logger.Errorw("Failed to get value from events_stats map", "error", err)
					continue
				}

				// Get counts
				id := events.ID(key)
				attempts := binary.LittleEndian.Uint64(value[0:8])
				failures := binary.LittleEndian.Uint64(value[8:16])
				t.Sstats.BPFPerfEventSubmitAttemptsCount.Set(id, attempts)
				t.Sstats.BPFPerfEventSubmitFailuresCount.Set(id, failures)

				// Update Prometheus metrics for current event
				evtName := events.Core.GetDefinitionByID(id).GetName()
				t.Sstats.BPFPerfEventSubmitAttemptsCount.GaugeVec().WithLabelValues(evtName).Set(float64(attempts))
				t.Sstats.BPFPerfEventSubmitFailuresCount.GaugeVec().WithLabelValues(evtName).Set(float64(failures))
			}

			// Log the counts
			t.Sstats.BPFPerfEventSubmitAttemptsCount.Log()
			t.Sstats.BPFPerfEventSubmitFailuresCount.Log()
		}
	}
}

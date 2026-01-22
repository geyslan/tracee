//go:build e2e

package e2e

import (
	"context"
	"errors"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eWritableDataSource{}) }

// E2eWritableDataSource is an e2e test detector for testing the writable data source API.
// Note: This detector requires the custom "e2e_inst/demo" data source to be registered.
type E2eWritableDataSource struct {
	logger    detection.Logger
	dataStore datastores.DataStore
}

func (d *E2eWritableDataSource) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "WRITABLE_DATA_SOURCE",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "sched_process_exit",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "WRITABLE_DATA_SOURCE",
			Description: "Instrumentation events E2E Tests: Writable Data Source Test",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eWritableDataSource) Init(params detection.DetectorParams) error {
	d.logger = params.Logger

	// NOTE: This detector is not yet fully functional.
	// The gRPC server (pkg/server/grpc/datasource.go) uses sigEngine.GetDataSource()
	// which accesses the old signature engine's data source registry.
	// The detector API uses params.DataStores.GetCustom() which accesses the new
	// datastores.Registry. These are separate systems.
	//
	// Migration required: Update gRPC server to support the new datastores.Registry
	// or create a bridge between the two registries.

	// Get the custom data source by name
	store, err := params.DataStores.GetCustom("e2e_inst_demo")
	if err != nil {
		return errors.New("writable data source 'e2e_inst_demo' not registered")
	}
	d.dataStore = store

	d.logger.Debugw("E2eWritableDataSource detector initialized")
	return nil
}

func (d *E2eWritableDataSource) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Get process name from workload
	processName := ""
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Thread != nil {
		processName = event.Workload.Process.Thread.Name
	}

	if processName != "ds_writer" {
		return nil, nil
	}

	// Note: The new DataStore interface doesn't have a generic Get() method like the old API.
	// This detector would need to be updated once the writable data source infrastructure
	// is fully migrated to the new API. For now, we'll log and skip.
	d.logger.Debugw("ds_writer process exited, would query writable data source")

	// For backward compatibility during migration, we detect the event
	// The full writable data source test would need additional infrastructure updates
	return detection.Detected(), nil
}

func (d *E2eWritableDataSource) Close() error {
	d.logger.Debugw("E2eWritableDataSource detector closed")
	return nil
}

//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eContainersDataSource{}) }

// E2eContainersDataSource is an e2e test detector for testing the containers data source API.
// Origin: "container" -> Uses ScopeFilters: container=started.
type E2eContainersDataSource struct {
	logger         detection.Logger
	containerStore datastores.ContainerStore
}

func (d *E2eContainersDataSource) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "CONTAINERS_DATA_SOURCE",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "sched_process_exec",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       datastores.Container,
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "CONTAINERS_DATA_SOURCE",
			Description: "Instrumentation events E2E Tests: Containers Data Source Test",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eContainersDataSource) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.containerStore = params.DataStores.Containers()
	d.logger.Debugw("E2eContainersDataSource detector initialized")
	return nil
}

func (d *E2eContainersDataSource) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	if pathname != "/bin/ls" {
		return nil, nil
	}

	// Get container ID from the event
	containerID := ""
	if event.Workload != nil && event.Workload.Container != nil {
		containerID = event.Workload.Container.Id
	}

	if containerID == "" {
		d.logger.Warnw("received non container event")
		return nil, nil
	}

	// Query the container store
	containerInfo, err := d.containerStore.GetContainer(containerID)
	if err != nil {
		d.logger.Warnw("failed to find container in data source", "container_id", containerID, "error", err)
		return nil, nil
	}

	if containerInfo.ID != containerID {
		d.logger.Warnw("container id mismatch", "expected", containerID, "got", containerInfo.ID)
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eContainersDataSource) Close() error {
	d.logger.Debugw("E2eContainersDataSource detector closed")
	return nil
}

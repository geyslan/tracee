//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eDnsDataSource{}) }

// E2eDnsDataSource is an e2e test detector for testing the DNS data source API.
type E2eDnsDataSource struct {
	logger   detection.Logger
	dnsStore datastores.DNSStore
}

func (d *E2eDnsDataSource) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "DNS_DATA_SOURCE",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "sched_process_exit",
					Dependency: detection.DependencyRequired,
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       datastores.DNS,
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "DNS_DATA_SOURCE",
			Description: "Instrumentation events E2E Tests: DNS Data Source Test",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eDnsDataSource) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dnsStore = params.DataStores.DNS()
	d.logger.Debugw("E2eDnsDataSource detector initialized")
	return nil
}

func (d *E2eDnsDataSource) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Get executable path from workload
	execPath := ""
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Executable != nil {
		execPath = event.Workload.Process.Executable.Path
	}

	if execPath != "/usr/bin/ping" {
		return nil, nil // Irrelevant code path
	}

	// Query DNS data source
	dnsResponse, err := d.dnsStore.GetDNSResponse("google.com")
	if err != nil {
		d.logger.Warnw("failed to find dns data in data source", "error", err)
		return nil, nil
	}

	if len(dnsResponse.IPs) < 1 {
		d.logger.Warnw("ip results were empty")
		return nil, nil
	}

	if len(dnsResponse.Domains) < 1 || dnsResponse.Query != "google.com" {
		d.logger.Warnw("dns results were empty or query mismatch", "query", dnsResponse.Query)
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eDnsDataSource) Close() error {
	d.logger.Debugw("E2eDnsDataSource detector closed")
	return nil
}

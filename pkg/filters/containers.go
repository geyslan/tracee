package filters

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type ContainerFilter struct {
	*BPFStringFilter
}

func NewContainerFilter(mapName string) *ContainerFilter {
	return &ContainerFilter{
		BPFStringFilter: NewBPFStringFilter(mapName),
	}
}

func (f *ContainerFilter) InitBPF(bpfModule *bpf.Module, containers *containers.Containers, filterScopeID uint) error {
	if !f.Enabled() {
		return nil
	}

	filterMap, err := bpfModule.GetMap(f.mapName)
	if err != nil {
		return err
	}

	filterVal := make([]byte, 16)

	for _, equalFilter := range f.Equal() {
		cgroupIDs := containers.FindContainerCgroupID32LSB(equalFilter)
		if cgroupIDs == nil {
			return fmt.Errorf("container id not found: %s", equalFilter)
		}
		if len(cgroupIDs) > 1 {
			return fmt.Errorf("container id is ambiguous: %s", equalFilter)
		}

		var bitmask, validBits uint64
		curVal, err := filterMap.GetValue(unsafe.Pointer(&cgroupIDs[0]))
		if err == nil {
			bitmask = binary.LittleEndian.Uint64(curVal[0:8])
			validBits = binary.LittleEndian.Uint64(curVal[8:16])
		}

		// filterEqual == 1, so set n bitmask bit
		utils.SetBit(&bitmask, filterScopeID)
		utils.SetBit(&validBits, filterScopeID)

		binary.LittleEndian.PutUint64(filterVal[0:8], bitmask)
		binary.LittleEndian.PutUint64(filterVal[8:16], validBits)
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&filterVal[0])); err != nil {
			return err
		}
	}

	for _, notEqualFilter := range f.NotEqual() {
		cgroupIDs := containers.FindContainerCgroupID32LSB(notEqualFilter)
		if cgroupIDs == nil {
			return fmt.Errorf("container id not found: %s", notEqualFilter)
		}
		if len(cgroupIDs) > 1 {
			return fmt.Errorf("container id is ambiguous: %s", notEqualFilter)
		}

		var bitmask, validBits uint64
		curVal, err := filterMap.GetValue(unsafe.Pointer(&cgroupIDs[0]))
		if err == nil {
			bitmask = binary.LittleEndian.Uint64(curVal[0:8])
			validBits = binary.LittleEndian.Uint64(curVal[8:16])
		}

		// filterNotEqual == 0, so clear n bitmask bit
		utils.ClearBit(&bitmask, filterScopeID)
		utils.SetBit(&validBits, filterScopeID)

		binary.LittleEndian.PutUint64(filterVal[0:8], bitmask)
		binary.LittleEndian.PutUint64(filterVal[8:16], validBits)
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&filterVal[0])); err != nil {
			return err
		}
	}

	return nil
}

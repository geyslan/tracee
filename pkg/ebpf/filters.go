package ebpf

import (
	"fmt"
	"net"
	"strings"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

const (
	UIDFilterMap         = "uid_filter"
	PIDFilterMap         = "pid_filter"
	MntNSFilterMap       = "mnt_ns_filter"
	PidNSFilterMap       = "pid_ns_filter"
	UTSFilterMap         = "uts_ns_filter"
	CommFilterMap        = "comm_filter"
	ProcessTreeFilterMap = "process_tree_map"
	CgroupIdFilterMap    = "cgroup_id_filter"
	ContIdFilter         = "cont_id_filter"
)

type FilterScope struct {
	ID                int
	EventsToTrace     []events.ID
	SetsToTrace       map[string]bool
	UIDFilter         *filters.BPFUIntFilter[uint32]
	PIDFilter         *filters.BPFUIntFilter[uint32]
	NewPidFilter      *filters.BoolFilter
	MntNSFilter       *filters.BPFUIntFilter[uint64]
	PidNSFilter       *filters.BPFUIntFilter[uint64]
	UTSFilter         *filters.BPFStringFilter
	CommFilter        *filters.BPFStringFilter
	ContFilter        *filters.BoolFilter
	NewContFilter     *filters.BoolFilter
	ContIDFilter      *filters.ContainerFilter
	RetFilter         *filters.RetFilter
	ArgFilter         *filters.ArgFilter
	ProcessTreeFilter *filters.ProcessTreeFilter
	Follow            bool
	NetFilter         *NetIfaces

	CheckEventsInUserSpace bool
	CheckSetsInUserSpace   bool
}

func NewFilterScope() FilterScope {
	return FilterScope{
		ID:                     0,
		EventsToTrace:          []events.ID{},
		SetsToTrace:            map[string]bool{},
		UIDFilter:              filters.NewBPFUInt32Filter(UIDFilterMap),
		PIDFilter:              filters.NewBPFUInt32Filter(PIDFilterMap),
		NewPidFilter:           filters.NewBoolFilter(),
		MntNSFilter:            filters.NewBPFUIntFilter(MntNSFilterMap),
		PidNSFilter:            filters.NewBPFUIntFilter(PidNSFilterMap),
		UTSFilter:              filters.NewBPFStringFilter(UTSFilterMap),
		CommFilter:             filters.NewBPFStringFilter(CommFilterMap),
		ContFilter:             filters.NewBoolFilter(),
		NewContFilter:          filters.NewBoolFilter(),
		ContIDFilter:           filters.NewContainerFilter(CgroupIdFilterMap),
		RetFilter:              filters.NewRetFilter(),
		ArgFilter:              filters.NewArgFilter(),
		ProcessTreeFilter:      filters.NewProcessTreeFilter(ProcessTreeFilterMap),
		Follow:                 false,
		NetFilter:              &NetIfaces{Ifaces: []string{}},
		CheckEventsInUserSpace: false,
		CheckSetsInUserSpace:   false,
	}
}

const MaxFilterScopes = 64

func isIDInRange(id int) bool {
	return id >= 0 && id < MaxFilterScopes
}

func (fs FilterScope) IsEventTraceable(event events.ID) bool {
	for _, e := range fs.EventsToTrace {
		if e == event {
			return true
		}
	}

	return false
}

func (fs FilterScope) IsSetTraceable(sets []string) bool {
	for _, s := range sets {
		if _, found := fs.SetsToTrace[s]; found {
			return true
		}
	}

	return false
}

type FilterScopes struct {
	filterScopesArray        [MaxFilterScopes]*FilterScope
	filterScopesMap          map[*FilterScope]int
	filterScopesUserSpaceMap map[*FilterScope]int

	uidFilterMin             uint64
	uidFilterMax             uint64
	pidFilterMin             uint64
	pidFilterMax             uint64
	uidFilterableInUserSpace bool
	pidFilterableInUserSpace bool
}

func NewFilterScopes() FilterScopes {
	return FilterScopes{
		filterScopesArray:        [MaxFilterScopes]*FilterScope{},
		filterScopesMap:          map[*FilterScope]int{},
		filterScopesUserSpaceMap: map[*FilterScope]int{},
		uidFilterMin:             filters.MinNotSetUInt,
		uidFilterMax:             filters.MaxNotSetUInt,
		pidFilterMin:             filters.MinNotSetUInt,
		pidFilterMax:             filters.MaxNotSetUInt,
		uidFilterableInUserSpace: false,
		pidFilterableInUserSpace: false,
	}
}

func (fs FilterScopes) Count() int {
	return len(fs.filterScopesMap)
}

func (fs FilterScopes) UIDFilterMin() uint64 {
	return fs.uidFilterMin
}

func (fs FilterScopes) UIDFilterMax() uint64 {
	return fs.uidFilterMax
}

func (fs FilterScopes) PIDFilterMin() uint64 {
	return fs.pidFilterMin
}

func (fs FilterScopes) PIDFilterMax() uint64 {
	return fs.pidFilterMax
}

func (fs FilterScopes) UIDFilterableInUserSpace() bool {
	return fs.uidFilterableInUserSpace
}

func (fs FilterScopes) PIDFilterableInUserSpace() bool {
	return fs.pidFilterableInUserSpace
}

// set, if not err, always reassign values
func (fs *FilterScopes) set(id int, scope *FilterScope) error {
	if scope == nil {
		return FilterScopeCannotBeNil{}
	}
	if !isIDInRange(id) {
		return &FilterScopesOutOfRangeError{
			Index: id,
		}
	}
	if _, found := fs.filterScopesMap[scope]; found {
		if scope.ID != id {
			return fmt.Errorf("filter scope [%+v] already set with different id [%d]", scope, id)
		}
	}

	scope.ID = id
	fs.filterScopesArray[id] = scope
	fs.filterScopesMap[scope] = id

	return nil
}

// Add adds a scope to FilterScopes.
// Its ID (index) is set to the first room found.
// Returns nil if scope is already inserted.
func (fs *FilterScopes) Add(scope *FilterScope) error {
	if len(fs.filterScopesMap) == MaxFilterScopes {
		return FilterScopesMaxExceededError{}
	}

	for id := range fs.filterScopesArray {
		if fs.filterScopesArray[id] == nil {
			return fs.set(id, scope)
		}
	}

	return nil
}

func (fs *FilterScopes) Set(id int, scope *FilterScope) error {
	return fs.set(id, scope)
}

// Delete deletes a scope from FilterScopes.
func (fs *FilterScopes) Delete(id int) error {
	if !isIDInRange(id) {
		return &FilterScopesOutOfRangeError{
			Index: id,
		}
	}
	if len(fs.filterScopesMap) == 0 {
		return nil
	}

	delete(fs.filterScopesMap, fs.filterScopesArray[id])
	delete(fs.filterScopesUserSpaceMap, fs.filterScopesArray[id])
	fs.filterScopesArray[id] = nil

	return nil
}

func (fs FilterScopes) Lookup(id int) (*FilterScope, error) {
	if !isIDInRange(id) {
		return nil, &FilterScopesOutOfRangeError{
			Index: id,
		}
	}

	scope := fs.filterScopesArray[id]
	if scope == nil {
		return nil, FilterScopeNotFound{
			Index: id,
		}
	}
	return scope, nil
}

func (fs FilterScopes) Map() map[*FilterScope]int {
	return fs.filterScopesMap
}

func (fs FilterScopes) ContainerFilterEnabled() bool {
	for filterScope := range fs.Map() {
		if filterScope.ContainerFilterEnabled() {
			return true
		}
	}

	return false
}

// UserSpaceMap returns a reduced scopes map which must be filtered in
// user space (ArgFilter, RetFilter, UIDFilter and PIDFilter).
func (fs FilterScopes) UserSpaceMap() map[*FilterScope]int {
	return fs.filterScopesUserSpaceMap
}

func (fs FilterScopes) Slice() []*FilterScope {
	var slice []*FilterScope

	for filterScope := range fs.filterScopesMap {
		slice = append(slice, filterScope)
	}

	return slice
}

// FillUserSpaceMap fills user space map
// It must be called after CalculateGlobalMinMax()
func (fs *FilterScopes) FillUserSpaceMap() {
	userSpaceMap := make(map[*FilterScope]int)

	for filterScope := range fs.filterScopesMap {
		if filterScope.CheckEventsInUserSpace ||
			filterScope.CheckSetsInUserSpace ||
			filterScope.ArgFilter.Enabled() ||
			filterScope.RetFilter.Enabled() ||
			(filterScope.UIDFilter.Enabled() && fs.UIDFilterableInUserSpace()) ||
			(filterScope.PIDFilter.Enabled() && fs.PIDFilterableInUserSpace()) {

			userSpaceMap[filterScope] = filterScope.ID
		}
	}

	fs.filterScopesUserSpaceMap = userSpaceMap
}

// CalculateGlobalMinMax sets the global min and max, to be checked in kernel space,
// of the Minimum and Maximum enabled filters only if context filter types (e.g. BPFUIDFilter)
// from all scopes have both Minimum and Maximum values set.
// FilterScopes user space filter flags are also set (e.g. uidFilterableInUserSpace).
//
// The context filter types relevant for this function are just UIDFilter and PIDFilter.
func (fs *FilterScopes) CalculateGlobalMinMax() {
	var (
		uidMinFilterCount int
		uidMaxFilterCount int
		uidFilterCount    int
		pidMinFilterCount int
		pidMaxFilterCount int
		pidFilterCount    int
		scopeCount        int

		uidMinFilterableInUserSpace bool
		uidMaxFilterableInUserSpace bool
		pidMinFilterableInUserSpace bool
		pidMaxFilterableInUserSpace bool
	)

	for filterScope := range fs.Map() {
		scopeCount++

		if filterScope.UIDFilter.Enabled() {
			uidFilterCount++

			if filterScope.UIDFilter.Minimum() != filters.MinNotSetUInt {
				uidMinFilterCount++
			}
			if filterScope.UIDFilter.Maximum() != filters.MaxNotSetUInt {
				uidMaxFilterCount++
			}
		}
		if filterScope.PIDFilter.Enabled() {
			pidFilterCount++

			if filterScope.PIDFilter.Minimum() != filters.MinNotSetUInt {
				pidMinFilterCount++
			}
			if filterScope.PIDFilter.Maximum() != filters.MaxNotSetUInt {
				pidMaxFilterCount++
			}
		}
	}
	uidMinFilterableInUserSpace = scopeCount > 1 && (uidMinFilterCount != uidFilterCount)
	uidMaxFilterableInUserSpace = scopeCount > 1 && (uidMaxFilterCount != uidFilterCount)
	pidMinFilterableInUserSpace = scopeCount > 1 && (pidMinFilterCount != pidFilterCount)
	pidMaxFilterableInUserSpace = scopeCount > 1 && (pidMaxFilterCount != pidFilterCount)

	// reset global min max
	fs.uidFilterMax = filters.MaxNotSetUInt
	fs.uidFilterMin = filters.MinNotSetUInt
	fs.pidFilterMax = filters.MaxNotSetUInt
	fs.pidFilterMin = filters.MinNotSetUInt

	fs.uidFilterableInUserSpace = uidMinFilterableInUserSpace || uidMaxFilterableInUserSpace
	fs.pidFilterableInUserSpace = pidMinFilterableInUserSpace || pidMaxFilterableInUserSpace

	if fs.UIDFilterableInUserSpace() && fs.PIDFilterableInUserSpace() {
		// there's no need to iterate filter scopes again since
		// all uint events will be submitted from ebpf with no regards

		return
	}

	// set a reduced range of uint values to be filtered in ebpf
	for filterScope := range fs.filterScopesMap {
		if filterScope.UIDFilter.Enabled() {
			if !uidMinFilterableInUserSpace {
				fs.uidFilterMin = utils.Min(fs.uidFilterMin, filterScope.UIDFilter.Minimum())
			}
			if !uidMaxFilterableInUserSpace {
				fs.uidFilterMax = utils.Max(fs.uidFilterMax, filterScope.UIDFilter.Maximum())
			}
		}
		if filterScope.PIDFilter.Enabled() {
			if !pidMinFilterableInUserSpace {
				fs.pidFilterMin = utils.Min(fs.pidFilterMin, filterScope.PIDFilter.Minimum())
			}
			if !pidMaxFilterableInUserSpace {
				fs.pidFilterMax = utils.Max(fs.pidFilterMax, filterScope.PIDFilter.Maximum())
			}
		}
	}
}

func (fs FilterScopes) IsFilterNetSet() bool {
	for filterScope := range fs.filterScopesMap {
		if len(filterScope.NetFilter.Interfaces()) > 0 {
			return true
		}
	}

	return false
}

func (fs FilterScope) ContainerFilterEnabled() bool {
	return (fs.ContFilter.Enabled() && fs.ContFilter.Value()) ||
		(fs.NewContFilter.Enabled() && fs.NewContFilter.Value()) ||
		fs.ContIDFilter.Enabled()
}

type NetIfaces struct {
	Ifaces []string
}

func (filter *NetIfaces) Parse(operatorAndValues string) error {
	ifaces := strings.Split(operatorAndValues, ",")
	filter.Ifaces = ifaces
	for _, iface := range ifaces {
		if _, err := net.InterfaceByName(iface); err != nil {
			return fmt.Errorf("invalid network interface: %s", iface)
		}
		_, found := filter.Find(iface)
		// if the interface is not already in the interface list, we want to add it
		if !found {
			filter.Ifaces = append(filter.Ifaces, iface)
		}
	}

	return nil
}

func (ifaces *NetIfaces) Find(iface string) (int, bool) {
	for idx, currIface := range ifaces.Ifaces {
		if currIface == iface {
			return idx, true
		}
	}

	return -1, false
}

func (ifaces *NetIfaces) Interfaces() []string {
	if ifaces.Ifaces == nil {
		ifaces.Ifaces = []string{}
	}
	return ifaces.Ifaces
}

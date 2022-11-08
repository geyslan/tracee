package flags

import (
	"fmt"
	"strconv"
	"strings"

	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
)

func filterHelp() string {
	return `Select which events to trace by defining trace expressions that operate on events or process metadata.
Only events that match all trace expressions will be traced (trace flags are ANDed).
The following types of expressions are supported:

Numerical expressions which compare numbers and allow the following operators: '=', '!=', '<', '>'.
Available numerical expressions: uid, pid, mntns, pidns.
NOTE: Expressions containing '<' or '>' token must be escaped! This is also shown in the examples below.

String expressions which compares text and allow the following operators: '=', '!='.
Available string expressions: event, set, uts, comm, container.

Boolean expressions that check if a boolean is true and allow the following operator: '!'.
Available boolean expressions: container.

Event arguments can be accessed using 'event_name.event_arg' and provide a way to filter an event by its arguments.
Event arguments allow the following operators: '=', '!='.
Strings can be compared as a prefix if ending with '*' or as suffix if starting with '*'.

Event return value can be accessed using 'event_name.retval' and provide a way to filter an event by its return value.
Event return value expression has the same syntax as a numerical expression.

Non-boolean expressions can compare a field to multiple values separated by ','.
Multiple values are ORed if used with equals operator '=', but are ANDed if used with any other operator.

The field 'container' and 'pid' also support the special value 'new' which selects new containers or pids, respectively.

The field 'set' selects a set of events to trace according to predefined sets, which can be listed by using the 'list' flag.

The special 'follow' expression declares that not only processes that match the criteria will be traced, but also their descendants.

The field 'net' specifies which interfaces to monitor when tracing network events.
Notice that the 'net' field is mandatory when tracing network events.

Examples:
  --trace pid=new                                              | only trace events from new processes
  --trace pid=510,1709                                         | only trace events from pid 510 or pid 1709
  --trace p=510 --trace p=1709                                 | only trace events from pid 510 or pid 1709 (same as above)
  --trace container=new                                        | only trace events from newly created containers
  --trace container_id=ab356bc4dd554                           | only trace events from container id ab356bc4dd554
  --trace container                                            | only trace events from containers
  --trace c                                                    | only trace events from containers (same as above)
  --trace '!container'                                         | only trace events from the host
  --trace uid=0                                                | only trace events from uid 0
  --trace mntns=4026531840                                     | only trace events from mntns id 4026531840
  --trace pidns!=4026531836                                    | only trace events from pidns id not equal to 4026531840
  --trace tree=476165                                          | only trace events that descend from the process with pid 476165
  --trace tree!=5023                                           | only trace events if they do not descend from the process with pid 5023
  --trace tree=3213,5200 --trace tree!=3215                    | only trace events if they descend from 3213 or 5200, but not 3215
  --trace 'uid>0'                                              | only trace events from uids greater than 0
  --trace 'pid>0' --trace 'pid<1000'                           | only trace events from pids between 0 and 1000
  --trace 'u>0' --trace u!=1000                                | only trace events from uids greater than 0 but not 1000
  --trace event=execve,open                                    | only trace execve and open events
  --trace event=open*                                          | only trace events prefixed by "open"
  --trace event!=open*,dup*                                    | don't trace events prefixed by "open" or "dup"
  --trace set=fs                                               | trace all file-system related events
  --trace s=fs --trace e!=open,openat                          | trace all file-system related events, but not open(at)
  --trace uts!=ab356bc4dd554                                   | don't trace events from uts name ab356bc4dd554
  --trace comm=ls                                              | only trace events from ls command
  --trace close.fd=5                                           | only trace 'close' events that have 'fd' equals 5
  --trace openat.pathname=/tmp*                                | only trace 'openat' events that have 'pathname' prefixed by "/tmp"
  --trace openat.pathname!=/tmp/1,/bin/ls                      | don't trace 'openat' events that have 'pathname' equals /tmp/1 or /bin/ls
  --trace comm=bash --trace follow                             | trace all events that originated from bash or from one of the processes spawned by bash
  --trace net=docker0 			                       | trace the net events over docker0 interface


Note: some of the above operators have special meanings in different shells.
To 'escape' those operators, please use single quotes, e.g.: 'uid>0'
`
}

func PrepareFilterScopes(filtersArr []string) (*tracee.FilterScopes, error) {
	eventsNameToID := events.Definitions.NamesToIDs()
	// remove internal events since they shouldn't be accesible by users
	for event, id := range eventsNameToID {
		if events.Definitions.Get(id).Internal {
			delete(eventsNameToID, event)
		}
	}

	processFilterFlag := func(filterFlag string) (filterName, operatorAndValues string, scopeIdx int, err error) {
		scopeID := 1
		operatorIndex := strings.IndexAny(filterFlag, "=!<>")
		if operatorIndex == -1 {
			return "", "", 0, filters.InvalidExpression(filterFlag)
		}

		dashIndex := strings.LastIndex(filterFlag[0:operatorIndex], "-")
		if dashIndex != -1 {
			if dashIndex+1 >= len(filterFlag) {
				return "", "", 0, 0, filters.InvalidScope(filterFlag)
			}
			scopeID, err = strconv.Atoi(filterFlag[dashIndex+1 : operatorIndex])
			if err != nil {
				return "", "", 0, 0, filters.InvalidScope(fmt.Sprintf("%s - %s", filterFlag, err))
			}
			if scopeIdx < 1 || scopeIdx > tracee.MaxFilterScopes {
				return "", "", 0, 0, filters.InvalidScope(fmt.Sprintf("%s - scopes must be between 1 and %d", filterFlag, tracee.MaxFilterScopes))
			}
		} else {
			dashIndex = operatorIndex
		}
		filterName = filterFlag[0:dashIndex]
		operatorAndValues = filterFlag[operatorIndex:]
		scopeIdx = scopeID - 1

		return
	}

	type processedFilterFlag struct {
		filterFlag        string
		filterName        string
		operatorAndValues string
	}
	processedScopesFilterFlags := map[int][]processedFilterFlag{}

	for _, filterFlag := range filtersArr {
		filterName, operatorAndValues, scopeIdx, err := processFilterFlag(filterFlag)
		if err != nil {
			return nil, err
		}
		if len(operatorAndValues) == 1 || operatorAndValues == "!=" || operatorAndValues == "<=" || operatorAndValues == ">=" {
			return nil, filters.InvalidExpression(filterFlag)
		}

		processedScopesFilterFlags[scopeIdx] = append(processedScopesFilterFlags[scopeIdx], processedFilterFlag{
			filterFlag:        filterFlag,
			filterName:        filterName,
			operatorAndValues: operatorAndValues,
		})
	}

	filterScopes := tracee.NewFilterScopes()
	for scopeIdx, scopeFilterFlags := range processedScopesFilterFlags {
		filterScope := tracee.NewFilterScope()
		eventFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}
		setFilter := cliFilter{
			Equal:    []string{},
			NotEqual: []string{},
		}

		for _, procFilterFlag := range scopeFilterFlags {

			if strings.Contains(procFilterFlag.filterFlag, ".retval") {
				err := filterScope.RetFilter.Parse(procFilterFlag.filterName, procFilterFlag.operatorAndValues, eventsNameToID)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.Contains(procFilterFlag.filterFlag, ".") {
				err := filterScope.ArgFilter.Parse(procFilterFlag.filterName, procFilterFlag.operatorAndValues, eventsNameToID)
				if err != nil {
					return nil, err
				}
				continue
			}

			// The filters which are more common (container, event, pid, set, uid) can be given using a prefix of them.
			// Other filters should be given using their full name.
			// To avoid collisions between filters that share the same prefix, put the filters which should have an exact match first!
			if procFilterFlag.filterName == "comm" {
				err := filterScope.CommFilter.Parse(procFilterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("container", procFilterFlag.filterName) {
				if procFilterFlag.operatorAndValues == "=new" {
					err := filterScope.NewContFilter.Parse("new")
					if err != nil {
						return nil, err
					}
					continue
				}
				if procFilterFlag.operatorAndValues == "!=new" {
					err := filterScope.ContFilter.Parse(procFilterFlag.filterName)
					if err != nil {
						return nil, err
					}
					err = filterScope.NewContFilter.Parse("!new")
					if err != nil {
						return nil, err
					}
					continue
				}
				if strings.Contains(procFilterFlag.operatorAndValues, "=") {
					err := filterScope.ContIDFilter.Parse(procFilterFlag.operatorAndValues)
					if err != nil {
						return nil, err
					}
					continue
				}
				err := filterScope.ContFilter.Parse(procFilterFlag.filterName)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("!container", procFilterFlag.filterName) {
				err := filterScope.ContFilter.Parse(procFilterFlag.filterName)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("event", procFilterFlag.filterName) {
				err := eventFilter.Parse(procFilterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				filterScope.CheckEventsInUserSpace = eventFilter.Enabled()
				continue
			}

			if strings.HasPrefix(procFilterFlag.filterName, "net") {
				err := filterScope.NetFilter.Parse(strings.TrimPrefix(procFilterFlag.operatorAndValues, "="))
				if err != nil {
					return nil, err
				}
				continue
			}

			if procFilterFlag.filterName == "mntns" {
				if strings.ContainsAny(procFilterFlag.operatorAndValues, "<>") {
					return nil, filters.InvalidExpression(procFilterFlag.operatorAndValues)
				}
				err := filterScope.MntNSFilter.Parse(procFilterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if procFilterFlag.filterName == "pidns" {
				if strings.ContainsAny(procFilterFlag.operatorAndValues, "<>") {
					return nil, filters.InvalidExpression(procFilterFlag.operatorAndValues)
				}
				err := filterScope.PidNSFilter.Parse(procFilterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if procFilterFlag.filterName == "tree" {
				err := filterScope.ProcessTreeFilter.Parse(procFilterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("pid", procFilterFlag.filterName) {
				if procFilterFlag.operatorAndValues == "=new" {
					filterScope.NewPidFilter.Parse("new")
					continue
				}
				if procFilterFlag.operatorAndValues == "!=new" {
					filterScope.NewPidFilter.Parse("!new")
					continue
				}
				err := filterScope.PIDFilter.Parse(procFilterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("set", procFilterFlag.filterName) {
				err := setFilter.Parse(procFilterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				filterScope.CheckSetsInUserSpace = setFilter.Enabled()
				continue
			}

			if procFilterFlag.filterName == "uts" {
				err := filterScope.UTSFilter.Parse(procFilterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("uid", procFilterFlag.filterName) {
				err := filterScope.UIDFilter.Parse(procFilterFlag.operatorAndValues)
				if err != nil {
					return nil, err
				}
				continue
			}

			if strings.HasPrefix("follow", procFilterFlag.filterFlag) {
				filterScope.Follow = true
				continue
			}

			return nil, InvalidFilterOptionError(procFilterFlag.filterFlag)
		}

		var err error
		filterScope.EventsToTrace, err = prepareEventsToTrace(eventFilter, setFilter, eventsNameToID)
		if err != nil {
			return nil, err
		}
		for _, eqSet := range setFilter.Equal {
			filterScope.SetsToTrace[eqSet] = true
		}

		if err := filterScopes.Set(scopeIdx, &filterScope); err != nil {
			return nil, err
		}
	}

	return &filterScopes, nil
}

func prepareEventsToTrace(eventFilter cliFilter, setFilter cliFilter, eventsNameToID map[string]events.ID) ([]events.ID, error) {
	eventsToTrace := eventFilter.Equal
	excludeEvents := eventFilter.NotEqual
	setsToTrace := setFilter.Equal

	var res []events.ID
	setsToEvents := make(map[string][]events.ID)
	isExcluded := make(map[events.ID]bool)
	for id, event := range events.Definitions.Events() {
		for _, set := range event.Sets {
			setsToEvents[set] = append(setsToEvents[set], id)
		}
	}
	for _, name := range excludeEvents {
		// Handle event prefixes with wildcards
		if strings.HasSuffix(name, "*") {
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) {
					isExcluded[id] = true
					found = true
				}
			}
			if !found {
				return nil, InvalidEventExcludeError(name)
			}
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, InvalidEventExcludeError(name)
			}
			isExcluded[id] = true
		}
	}
	if len(eventsToTrace) == 0 && len(setsToTrace) == 0 {
		setsToTrace = append(setsToTrace, "default")
	}

	res = make([]events.ID, 0, events.Definitions.Length())
	for _, name := range eventsToTrace {
		// Handle event prefixes with wildcards
		if strings.HasSuffix(name, "*") {
			var ids []events.ID
			found := false
			prefix := name[:len(name)-1]
			for event, id := range eventsNameToID {
				if strings.HasPrefix(event, prefix) && !isExcluded[id] {
					ids = append(ids, id)
					found = true
				}
			}
			if !found {
				return nil, InvalidEventError(name)
			}
			res = append(res, ids...)
		} else {
			id, ok := eventsNameToID[name]
			if !ok {
				return nil, InvalidEventError(name)
			}
			res = append(res, id)
		}
	}
	for _, set := range setsToTrace {
		setEvents, ok := setsToEvents[set]
		if !ok {
			return nil, InvalidSetError(set)
		}
		for _, id := range setEvents {
			if !isExcluded[id] {
				res = append(res, id)
			}
		}
	}
	return res, nil
}

type cliFilter struct {
	Equal    []string
	NotEqual []string
}

func (filter *cliFilter) Parse(operatorAndValues string) error {
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		switch operatorString {
		case "=":
			filter.Equal = append(filter.Equal, values[i])
		case "!=":
			filter.NotEqual = append(filter.NotEqual, values[i])
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func (filter *cliFilter) Enabled() bool {
	return len(filter.Equal) > 0 || len(filter.NotEqual) > 0
}

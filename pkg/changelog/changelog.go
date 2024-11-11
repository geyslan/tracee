package changelog

import (
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
)

//
// Entries
//

// MemberKind represents the unique identifier for each kind of entry in the Entries.
// It is used to categorize different kinds of changes tracked by the Entries.
type MemberKind uint8

// MaxEntries represents the maximum number of entries that can be stored for a given kind of entry.
type MaxEntries uint8

// entry is an internal structure representing a single change in the Entries.
// It includes the kind of the entry, the timestamp of the change, and the value of the change.
type entry[T comparable] struct {
	k     MemberKind // Kind of the member, used to categorize the entry.
	t     time.Time  // Timestamp of when the change occurred.
	value T          // Value of the change.
}

// Entries is the main structure that manages a list of changes (entries).
// It keeps track of specifically configured members indicated by MemberKind identifiers.
// When instantiating an Entries struct, one must supply a relevant mapping between the desired
// unique members and the maximum amount of changes that member can track.
//
// ATTENTION: You should use Entries within a struct and provide methods to access it,
// coordinating access through your struct mutexes. DO NOT EXPOSE the Entries object directly to
// the outside world as it is not thread-safe.
type Entries[T comparable] struct {
	entryFlags []MaxEntries // Configuration slice defining flags for each member kind.
	entries    []entry[T]   // List of recorded entries.
}

// NewEntries initializes a new `Entries` structure using the provided flags.
func NewEntries[T comparable](f []MaxEntries) *Entries[T] {
	flags := make([]MaxEntries, 0, len(f))
	for _, maxEntries := range f {
		if maxEntries == 0 {
			logger.Fatalw("maxEntries must be greater than 0")
		}

		flags = append(flags, maxEntries)
	}

	return &Entries[T]{
		entryFlags: flags,
		entries:    []entry[T]{},
	}
}

// Set adds or updates an entry in the Entries for the specified `MemberKind` ordered by timestamp.
// If the new entry has the same value as the latest one, only the timestamp is updated.
// If there are already the maximum number of entries for this kind, it reuses or replaces an existing entry.
//
// ATTENTION: Make sure to pass a value of the correct type for the specified `MemberKind`.
func (e *Entries[T]) Set(k MemberKind, value T, t time.Time) {
	if k >= MemberKind(len(e.entryFlags)) {
		logger.Errorw("kind is not present in the entryFlags", "kind", k)
	}

	maxEntries := e.entryFlags[k]
	maxSize := int(maxEntries)
	indexes := make([]int, 0)

	// collect indexes of entries equal to kind
	for idx, entry := range e.entries {
		if entry.k == k {
			indexes = append(indexes, idx)
		}
	}

	// if there are entries for kind check if the last entry has the same value
	if len(indexes) > 0 {
		lastIdx := indexes[len(indexes)-1]
		if e.entries[lastIdx].value == value && t.After(e.entries[lastIdx].t) {
			// only update timestamp and return
			e.entries[lastIdx].t = t
			return
		}
	}

	newEntry := entry[T]{
		k:     k,
		t:     t,
		value: value,
	}

	//
	// if there is space, insert the new entry at the correct position
	//

	if len(indexes) < maxSize {
		insertPos := e.findInsertIdx(indexes, t)
		if insertPos == len(e.entries) {
			e.entries = append(e.entries, newEntry)
			return
		}

		e.insertAt(insertPos, newEntry)
		return
	}

	//
	// as there is no space, replace an entry
	//

	replaceIdx := indexes[len(indexes)-1] // default index to replace
	if t.After(e.entries[replaceIdx].t) {
		// reallocate values to the left
		e.shiftLeft(indexes)
	} else {
		// find the correct position to store the entry
		replaceIdx = e.findInsertIdx(indexes, t) - 1
		if replaceIdx == -1 {
			replaceIdx = 0
		}
	}
	e.entries[replaceIdx] = newEntry
}

// Get retrieves the value of the entry for the specified `MemberKind` at or before the given timestamp.
// If no matching entry is found, it returns the default value for the entry type.
func (e *Entries[T]) Get(k MemberKind, timestamp time.Time) T {
	for i := len(e.entries) - 1; i >= 0; i-- {
		if e.entries[i].k != k {
			continue
		}

		if e.entries[i].t.Before(timestamp) || e.entries[i].t.Equal(timestamp) {
			return e.entries[i].value
		}
	}

	return getZero[T]()
}

// GetCurrent retrieves the most recent value for the specified `MemberKind`.
// If no entry is found, it returns the default value for the entry type.
func (e *Entries[T]) GetCurrent(k MemberKind) T {
	for i := len(e.entries) - 1; i >= 0; i-- {
		if e.entries[i].k == k {
			return e.entries[i].value
		}
	}

	return getZero[T]()
}

// GetAll retrieves all values for the specified `MemberKind`, from the newest to the oldest.
func (e *Entries[T]) GetAll(k MemberKind) []T {
	values := make([]T, e.Count(k))
	for i := len(e.entries) - 1; i >= 0; i-- {
		if e.entries[i].k == k {
			values = append(values, e.entries[i].value)
		}
	}

	return values
}

// Count returns the number of entries recorded for the specified `MemberKind`.
func (e *Entries[T]) Count(k MemberKind) int {
	count := 0
	for _, entry := range e.entries {
		if entry.k == k {
			count++
		}
	}

	return count
}

// findInsertIdx finds the correct index to insert a new entry based on its timestamp.
func (e *Entries[T]) findInsertIdx(indexes []int, t time.Time) int {
	for i := len(indexes) - 1; i >= 0; i-- {
		if e.entries[indexes[i]].t.Before(t) {
			return indexes[i] + 1
		}
	}

	return len(indexes)
}

// insertAt inserts a new entry at the specified index in the entries list.
func (e *Entries[T]) insertAt(idx int, newEntry entry[T]) {
	e.entries = append(e.entries[:idx], append([]entry[T]{newEntry}, e.entries[idx:]...)...)
}

// shiftLeft shifts entries within the given indexes to the left, discarding the oldest entry.
func (e *Entries[T]) shiftLeft(indexes []int) {
	for i := 0; i < len(indexes)-1; i++ {
		e.entries[indexes[i]] = e.entries[indexes[i+1]]
	}
}

// getZero returns the zero value for the type `T`.
func getZero[T comparable]() T {
	var zero T
	return zero
}

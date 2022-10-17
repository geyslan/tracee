package ebpf

import "fmt"

type FilterScopeCannotBeNil struct {
	Err error
}

func (fse FilterScopeCannotBeNil) Error() string {
	return "filter scope cannot be nil"
}

type FilterScopeNotFound struct {
	Err   error
	Index int
}

func (fse FilterScopeNotFound) Error() string {
	return fmt.Sprintf("filter scope not found at index [%d]", fse.Index)
}

type FilterScopesMaxExceededError struct {
	Err error
}

func (fse FilterScopesMaxExceededError) Error() string {
	return fmt.Sprintf("filter scopes maximum exceeded [%d]", MaxFilterScopes)
}

type FilterScopesOutOfRangeError struct {
	Err   error
	Index int
}

func (fse FilterScopesOutOfRangeError) Error() string {
	return fmt.Sprintf("filter scopes index [%d] out-of-range [0-%d]", fse.Index, MaxFilterScopes-1)
}

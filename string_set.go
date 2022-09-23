package jvbuster

type StringSet map[string]struct{}

var exists = struct{}{}

func NewStringSet() StringSet {
	return make(StringSet)
}

func NewStringSetSized(size int) StringSet {
	return make(StringSet, size)
}

func NewStringSetFromSlice(elems []string) StringSet {
	set := NewStringSetSized(len(elems))
	for _, elem := range elems {
		set.Add(elem)
	}
	return set
}

func (set StringSet) Add(elem string) {
	set[elem] = exists
}

func (set StringSet) Remove(elem string) {
	delete(set, elem)
}

func (set StringSet) GetSlice() []string {
	elems := make([]string, 0, len(set))
	for elem := range set {
		elems = append(elems, elem)
	}
	return elems
}

func (set StringSet) Contains(elem string) bool {
	_, contains := set[elem]
	return contains
}

func (set StringSet) Equals(anotherSet StringSet) bool {
	if len(set) != len(anotherSet) {
		return false
	}
	for elem := range set {
		if !anotherSet.Contains(elem) {
			return false
		}
	}
	return true
}

func (set StringSet) Clear() {
	for elem := range set {
		delete(set, elem)
	}
}

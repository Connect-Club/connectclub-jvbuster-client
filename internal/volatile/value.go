package volatile

import "sync/atomic"

type Value[T any] atomic.Value

func NewValue[T any](val T) *Value[T] {
	v := &Value[T]{}
	(*atomic.Value)(v).Store(val)
	return v
}

func (v *Value[T]) Load() T {
	return (*atomic.Value)(v).Load().(T)
}

func (v *Value[T]) Store(val T) {
	(*atomic.Value)(v).Store(val)
}

func (v *Value[T]) Swap(new T) T {
	return (*atomic.Value)(v).Swap(new).(T)
}

package jvbuster

import (
	"context"
	"errors"
	"time"
)

type Task struct {
	done   chan Signal
	tasks  chan Signal
	cancel context.CancelFunc
}

func CreateTask(fn func(ctx context.Context), sleepDuration time.Duration, allowSchedule bool) *Task {
	ctx, cancel := context.WithCancel(context.Background())

	signalChanSize := 0
	if allowSchedule {
		signalChanSize = 1
	}

	task := &Task{
		done:   make(chan Signal),
		tasks:  make(chan Signal, signalChanSize),
		cancel: cancel,
	}
	go func() {
		defer close(task.done)
	cycle:
		for {
			select {
			case <-ctx.Done():
				break cycle
			case <-task.tasks:
				fn(ctx)
			}

			select {
			case <-ctx.Done():
				break cycle
			case <-time.After(sleepDuration):
			}
		}
	}()
	return task
}

func (task *Task) Run() {
	select {
	case task.tasks <- SignalInstance:
	default:
	}
}

func (task *Task) SyncRun(timeout time.Duration) error {
	select {
	case task.tasks <- SignalInstance:
		return nil
	case <-time.After(timeout):
		return errors.New("timeout")
	}
}

func (task *Task) Stop(timeout time.Duration) error {
	task.cancel()

	select {
	case <-task.done:
		return nil
	case <-time.After(timeout):
		return errors.New("timeout")
	}
}

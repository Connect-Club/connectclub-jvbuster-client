package jvbuster

type Signal struct{}

var SignalInstance Signal

func clearSignalChan(ch chan Signal) {
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

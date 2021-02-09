package signals

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

var (
	onlyOneSignalHandler = make(chan struct{})
	shutdownSignals      = []os.Signal{os.Interrupt, syscall.SIGTERM}
)

// SetupSignalHandler registered for SIGTERM and SIGINT. A stop channel is
// returned which is closed on one of these signals. If a second signal is
// caught, the program is terminated with exit code 1. It also cancels the
// global context on the first SIGTERM/SIGINT
func SetupSignalHandler(cancel context.CancelFunc) (stopCh <-chan struct{}) {
	close(onlyOneSignalHandler) // panics when called twice

	stop := make(chan struct{})
	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		// This will close the workqueue and signal that it should stop
		// accepting items
		close(stop)
		// This will cancel the global context and all pending connections that
		// any controller might have
		cancel()
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return stop
}

func ShutDown() error {
	return syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
}

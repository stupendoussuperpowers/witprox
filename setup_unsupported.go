//go:build !linux

package main

func setupTracing() {
	log.Fatalf("Network tracing not supported on this platform")
}

func cleanUpTracing() {}

func runServers() {}

func createComm() CommServer {
	return nil
}

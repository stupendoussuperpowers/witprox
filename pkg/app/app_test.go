package app

import (
	"testing"

	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
)

func TestStoreLog_FIFOEviction(t *testing.T) {
	InitNetworkStore()

	// Store PIDs 0-99
	for i := uint32(0); i < 100; i++ {
		pkt := networklog.Packet{}
		StoreLog(i, pkt)
	}

	// Add PIDs 100-102, should evict 0, 1, 2
	for i := uint32(100); i < 103; i++ {
		pkt := networklog.Packet{}
		StoreLog(i, pkt)
	}

	mapMu.Lock()
	defer mapMu.Unlock()

	// Check evicted PIDs
	for i := uint32(0); i < 3; i++ {
		if _, exists := NetworkStore[i]; exists {
			t.Errorf("Expected PID %d to be evicted", i)
		}
	}

	// Check remaining PIDs
	for i := uint32(3); i < 103; i++ {
		if _, exists := NetworkStore[i]; !exists {
			t.Errorf("Expected PID %d to exist", i)
		}
	}

	// Check pidOrder matches
	if pidOrder[0] != uint32(3) {
		t.Errorf("Expected first in order to be 3, got %d", pidOrder[0])
	}

	if pidOrder[len(pidOrder)-1] != uint32(102) {
		t.Errorf("Expected last in order to be 102, got %d", pidOrder[len(pidOrder)-1])
	}
}

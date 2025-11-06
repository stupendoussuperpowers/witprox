package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// The eBPF binaries are embedded below. Use make all to ensure these .o files
// are present in the correct location.

//go:embed internal/bpf/witprox.o
var witproxObj []byte

//go:embed internal/bpf/redirect.o
var redirectObj []byte

var CGROUP_REDIRECT = "/sys/fs/cgroup/redirect"
var CGROUP_WITPROX = "/sys/fs/cgroup/witprox"

func setupEBPF() []link.Link {
	// Load redirect object, and pin all the maps.
	log.Infof("Setting up eBFP...")
	redirectColl, err := pinMaps(redirectObj, "/sys/fs/bpf/")
	if err != nil {
		log.Fatal(err)
	}

	defer redirectColl.Close()

	witproxSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(witproxObj))
	if err != nil {
		log.Fatal(err)
	}

	// PinByName ensures that the maps are shared between the two programs.
	for name, m := range witproxSpec.Maps {
		switch name {
		case "client_map":
			m.Pinning = ebpf.PinByName
		case "t_2_c":
			m.Pinning = ebpf.PinByName
		case "server_map":
			m.Pinning = ebpf.PinByName
		}
	}

	witproxColl, err := ebpf.NewCollectionWithOptions(witproxSpec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		}})

	if err != nil {
		log.Fatal(err)
	}

	defer witproxColl.Close()

	createCgroup(CGROUP_REDIRECT)
	createCgroup(CGROUP_WITPROX)

	// Pin both programs so that they can be attached later.
	os.MkdirAll("/sys/fs/bpf/redirect", 0755)
	os.MkdirAll("/sys/fs/bpf/witprox", 0755)
	for name, m := range redirectColl.Programs {
		pp := filepath.Join("/sys/fs/bpf/redirect", name)
		if err := m.Pin(pp); err != nil {
			log.Fatalf("pin prog %s: %v", name, err)
		}
		log.Infof("pinned prog %s to %s", name, pp)
	}

	for name, m := range witproxColl.Programs {
		pp := filepath.Join("/sys/fs/bpf/witprox", name)
		if err := m.Pin(pp); err != nil {
			log.Fatalf("pin prog %s: %v", name, err)
		}
		log.Infof("pinned prog %s to %s", name, pp)
	}

	programLinks := make([]link.Link, 0)

	programLinks = append(programLinks, attachProgram("redirect", "track_conn", ebpf.AttachCGroupSockOps))
	programLinks = append(programLinks, attachProgram("redirect", "redirect_connect4", ebpf.AttachCGroupInet4Connect))

	programLinks = append(programLinks, attachProgram("witprox", "track_conn", ebpf.AttachCGroupSockOps))

	// The attachments are only valid so long as their links are still in memory.
	// To ensure that the GC doesn't eat them up, we return it and store it in a global variable.
	return programLinks
}

func cleanUpEBPF() {
	// Remove the attached programs.
	log.Infof("Tearing down eBPF setups")
	if activeLinks != nil {
		for _, l := range activeLinks {
			if err := l.Close(); err != nil {
				log.Infof("error closing link: %v", err)
			}
		}
		activeLinks = nil
	}

	// Delete all pins.
	pinnedObjects := []string{
		"/sys/fs/bpf/client_map",
		"/sys/fs/bpf/t_2_c",
		"/sys/fs/bpf/server_map",
		"/sys/fs/bpf/redirect/track_conn",
		"/sys/fs/bpf/redirect/redirect_connect4",
		"/sys/fs/bpf/witprox/track_conn",
		"/sys/fs/bpf/witprox/",
		"/sys/fs/bpf/redirect/",
	}

	for _, path := range pinnedObjects {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Infof("failed to remove pinned map: %s: %v", path, err)
		}
	}

	// Delete cgroups.
	for _, cg := range []string{CGROUP_REDIRECT, CGROUP_WITPROX} {
		if err := os.Remove(cg); err != nil && !os.IsNotExist(err) {
			log.Infof("failed to remove cgroup %s: %v", cg, err)
		}
	}

	log.Info("eBPF cleanup complete.")
}

func pinMaps(bpfBytes []byte, pinPath string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytes))
	if err != nil {
		return nil, log.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, log.Errorf("create collection: %w", err)
	}

	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return nil, log.Errorf("mkdir pin path: %w", err)
	}

	for name, m := range coll.Maps {
		if m == nil || strings.Contains(name, "rodata") {
			continue
		}
		p := filepath.Join(pinPath, name)
		if err := m.Pin(p); err != nil {
			return nil, log.Errorf("pin map %s: %w", name, err)
		}
	}

	return coll, nil
}

func createCgroup(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil && !os.IsExist(err) {
		return log.Errorf("mkdir cgroup: %w", err)
	}

	return nil
}

func attachProgram(cgroup string, path string, attachType ebpf.AttachType) link.Link {
	pinnedProg, _ := ebpf.LoadPinnedProgram(fmt.Sprintf("/sys/fs/bpf/%s/%s", cgroup, path), nil)
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/" + cgroup,
		Attach:  attachType,
		Program: pinnedProg,
	})

	if err != nil {
		log.Fatalf("attach cgroup: witness track_conn")
	}

	return l
}

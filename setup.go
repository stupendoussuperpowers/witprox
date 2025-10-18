package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed internal/bpf/witprox.o
var witproxObj []byte

//go:embed internal/bpf/redirect.o
var redirectObj []byte

func pinMaps(bpfBytes []byte, pinPath string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytes))
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return nil, fmt.Errorf("mkdir pin path: %w", err)
	}

	for name, m := range coll.Maps {
		p := filepath.Join(pinPath, name)
		if err := m.Pin(p); err != nil {
			return nil, fmt.Errorf("pin map %s: %w", name, err)
		}
	}

	return coll, nil
}

func createCgroup(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("mkdir cgroup: %w", err)
	}

	return nil
}

func moveToCgroup(pid int, cgroup string) error {
	tasks := filepath.Join(cgroup, "cgroup.procs")
	return os.WriteFile(tasks, []byte(fmt.Sprintf("%d", pid)), 0644)
}

func SetupEBPF() []link.Link {
	redirectColl, err := pinMaps(redirectObj, "/sys/fs/bpf/")
	if err != nil {
		log.Fatal(err)
	}

	defer redirectColl.Close()

	witproxSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(witproxObj))
	if err != nil {
		log.Fatal(err)
	}

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

	createCgroup("/sys/fs/cgroup/redirect")
	createCgroup("/sys/fs/cgroup/witprox")

	os.MkdirAll("/sys/fs/bpf/redirect", 0755)
	os.MkdirAll("/sys/fs/bpf/witprox", 0755)
	for name, m := range redirectColl.Programs {
		pp := filepath.Join("/sys/fs/bpf/redirect", name)
		if err := m.Pin(pp); err != nil {
			log.Fatalf("pin prog %s: %v", name, err)
		}
		log.Printf("pinned prof %s to %s", name, pp)
	}

	for name, m := range witproxColl.Programs {
		pp := filepath.Join("/sys/fs/bpf/witprox", name)
		if err := m.Pin(pp); err != nil {
			log.Fatalf("pin prog %s: %v", name, err)
		}
		log.Printf("pinned prof %s to %s", name, pp)
	}

	programLinks := make([]link.Link, 0)
	programLinks = append(programLinks, AttachProgram("redirect", "track_conn", ebpf.AttachCGroupSockOps))
	programLinks = append(programLinks, AttachProgram("redirect", "redirect_connect4", ebpf.AttachCGroupInet4Connect))

	programLinks = append(programLinks, AttachProgram("witprox", "track_conn", ebpf.AttachCGroupSockOps))

	//moveToCgroup(os.Getpid(), "/sys/fs/cgroup/witprox")

	return programLinks
}

func CleanUpEBPF() {
	// Remove the attached programs.
	if activeLinks != nil {
		for _, l := range activeLinks {
			if err := l.Close(); err != nil {
				log.Printf("error closing link: %v", err)
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
	}

	for _, path := range pinnedObjects {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("failed to remove pinned map: %s: %v", path, err)
		}
	}

	// Delete cgroups.

	moveToCgroup(os.Getpid(), "/sys/fs/cgroup/unified")

	cgroups := []string{
		"/sys/fs/cgroup/redirect",
		"/sys/fs/cgroup/witprox",
	}

	for _, cg := range cgroups {
		if err := os.Remove(cg); err != nil && !os.IsNotExist(err) {
			log.Printf("failed to remove cgruop %s: %v", cg, err)
		}
	}

	log.Println("eBPF cleanup complete.")
}

func AttachProgram(cgroup string, path string, attachType ebpf.AttachType) link.Link {
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

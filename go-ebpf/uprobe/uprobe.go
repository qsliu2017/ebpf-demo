package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed uprobe.bpf.o
var _bpfBytes []byte

var binPath string = "/usr/local/pgsql/bin/postgres"

type bpfSpec struct {
	Uprobe *ebpf.ProgramSpec `ebpf:"uprobe"`
	Events *ebpf.MapSpec     `ebpf:"events"`
}

type bpfObj struct {
	Uprobe *ebpf.Program `ebpf:"uprobe"`
	Events *ebpf.Map     `ebpf:"events"`
}

type event struct {
	Pid    uint64
	Ts     uint64
	Cookie uint64
}

func init() {
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_bpfBytes))
	if err != nil {
		panic(err)
	}

	obj := bpfObj{}
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		panic(err)
	}
	defer obj.Events.Close()
	defer obj.Uprobe.Clone()

	exec, err := link.OpenExecutable(binPath)
	if err != nil {
		panic(err)
	}

	var probeCnt int
	probeName := make(map[int]string)

	r := bufio.NewReader(os.Stdin)
	for {
		symname, _, err := r.ReadLine()
		if err != nil {
			break
		}
		link, err := exec.Uprobe(string(symname), obj.Uprobe, &link.UprobeOptions{Cookie: uint64(probeCnt)})
		if err != nil {
			fmt.Printf("%v", err)
		}
		defer link.Close()
		probeName[probeCnt] = string(symname)
		probeCnt++
	}

	rd, err := perf.NewReader(obj.Events, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	fmt.Println("start to trace")

	var e event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			fmt.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			fmt.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			fmt.Printf("parsing perf event: %s", err)
			continue
		}

		if _, has := probeName[int(e.Cookie)]; has {
			fmt.Printf("entry function: %s\n", probeName[int(e.Cookie)])
		} else {
			fmt.Printf("unknown cookie: %d\n", e.Cookie)
		}
	}
}

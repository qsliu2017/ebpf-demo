package main

import (
	"bytes"
	"debug/elf"
	_ "embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed uprobe.bpf.o
var _bpfBytes []byte

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

var (
	pid     int
	binPath string
)

func init() {
	flag.IntVar(&pid, "pid", 0, "")
	flag.StringVar(&binPath, "bin", "", "")

	flag.Parse()
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

	f, err := elf.Open("/usr/local/pgsql/bin/postgres")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	symbols, err := f.Symbols()
	if err != nil {
		panic(err)
	}
	for _, sym := range symbols {
		if sym.Info != byte(elf.STT_FUNC) {
			continue
		}
		link, err := exec.Uprobe(sym.Name, obj.Uprobe, &link.UprobeOptions{Cookie: uint64(probeCnt), PID: pid})
		if err != nil {
			fmt.Printf("%v", err)
		}
		defer link.Close()
		probeName[probeCnt] = sym.Name
		probeCnt++
	}

	rd, err := perf.NewReader(obj.Events, os.Getpagesize()*(1<<6))
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

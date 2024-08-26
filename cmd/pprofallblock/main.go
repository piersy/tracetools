package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/FiloSottile/tracetools/pprof"
	"github.com/FiloSottile/tracetools/trace"
)

var usageMessage = `Usage: pprofsyscall trace.out > syscall.pprof`

func filterStack(Stk []*trace.Frame, re *regexp.Regexp) bool {
	for _, f := range Stk {
		if re.FindStringIndex(f.Fn) != nil {
			return true
		}
	}
	return false
}

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, usageMessage)
		os.Exit(2)
	}
	flag.Parse()

	var traceFile string
	switch flag.NArg() {
	case 1:
		traceFile = flag.Arg(0)
	default:
		flag.Usage()
	}

	events, err := pprof.LoadTrace(traceFile, "")
	if err != nil {
		log.Fatal(err)
	}

	err = computePprofAll(os.Stdout, nil, events)
	if err != nil {
		log.Fatal(err)
	}
}

// computePprofSyscall generates syscall pprof-like profile (time spent blocked in syscalls).
func computePprofAll(w io.Writer, gToIntervals map[uint64][]pprof.Interval, events []*trace.Event) error {
	prof := make(map[uint64]pprof.Record)
	for _, ev := range events {
		if ev.Link == nil || ev.StkID == 0 || len(ev.Stk) == 0 {
			continue
		}
		switch ev.Type {
		case trace.EvGoBlockSend, trace.EvGoBlockRecv, trace.EvGoBlockSelect,
			trace.EvGoBlockSync, trace.EvGoBlockCond, trace.EvGoSysCall, trace.EvGoBlockNet:
		default:
			continue
		}

		overlapping := pprofOverlappingDuration(gToIntervals, ev)
		if overlapping > 0 {
			rec := prof[ev.StkID]
			rec.Stk = ev.Stk
			rec.N++
			rec.Time += overlapping.Nanoseconds()
			prof[ev.StkID] = rec
		}
	}
	return pprof.BuildProfile(prof).Write(w)
}

// // computePprofIO generates IO pprof-like profile (time spent in IO wait, currently only network blocking event).
// func computePprofIO(w io.Writer, gToIntervals map[uint64][]interval, events []*trace.Event) error {
// 	prof := make(map[uint64]Record)
// 	for _, ev := range events {
// 		if ev.Type != trace.EvGoBlockNet || ev.Link == nil || ev.StkID == 0 || len(ev.Stk) == 0 {
// 			continue
// 		}
// 		overlapping := pprofOverlappingDuration(gToIntervals, ev)
// 		if overlapping > 0 {
// 			rec := prof[ev.StkID]
// 			rec.stk = ev.Stk
// 			rec.n++
// 			rec.time += overlapping.Nanoseconds()
// 			prof[ev.StkID] = rec
// 		}
// 	}
// 	return buildProfile(prof).Write(w)
// }

// computePprofBlock generates blocking pprof-like profile (time spent blocked on synchronization primitives).
// func computePprofBlock(w io.Writer, gToIntervals map[uint64][]interval, events []*trace.Event) error {
// 	prof := make(map[uint64]Record)
// 	for _, ev := range events {
// 		switch ev.Type {
// 		case trace.EvGoBlockSend, trace.EvGoBlockRecv, trace.EvGoBlockSelect,
// 			trace.EvGoBlockSync, trace.EvGoBlockCond, trace.EvGoBlockGC:
// 			// TODO(hyangah): figure out why EvGoBlockGC should be here.
// 			// EvGoBlockGC indicates the goroutine blocks on GC assist, not
// 			// on synchronization primitives.
// 		default:
// 			continue
// 		}
// 		if ev.Link == nil || ev.StkID == 0 || len(ev.Stk) == 0 {
// 			continue
// 		}
// 		overlapping := pprofOverlappingDuration(gToIntervals, ev)
// 		if overlapping > 0 {
// 			rec := prof[ev.StkID]
// 			rec.stk = ev.Stk
// 			rec.n++
// 			rec.time += overlapping.Nanoseconds()
// 			prof[ev.StkID] = rec
// 		}
// 	}
// 	return buildProfile(prof).Write(w)
// }

// func pprofByGoroutine(compute func(io.Writer, map[uint64][]interval, []*trace.Event) error) func(w io.Writer, r *http.Request) error {
// 	return func(w io.Writer, r *http.Request) error {
// 		id := r.FormValue("id")
// 		events, err := parseEvents()
// 		if err != nil {
// 			return err
// 		}
// 		gToIntervals, err := pprofMatchingGoroutines(id, events)
// 		if err != nil {
// 			return err
// 		}
// 		return compute(w, gToIntervals, events)
// 	}
// }

// pprofOverlappingDuration returns the overlapping duration between
// the time intervals in gToIntervals and the specified event.
// If gToIntervals is nil, this simply returns the event's duration.
func pprofOverlappingDuration(gToIntervals map[uint64][]pprof.Interval, ev *trace.Event) time.Duration {
	if gToIntervals == nil { // No filtering.
		return time.Duration(ev.Link.Ts-ev.Ts) * time.Nanosecond
	}
	intervals := gToIntervals[ev.G]
	if len(intervals) == 0 {
		return 0
	}

	var overlapping time.Duration
	for _, i := range intervals {
		if o := overlappingDuration(i.Begin, i.End, ev.Ts, ev.Link.Ts); o > 0 {
			overlapping += o
		}
	}
	return overlapping
}

// overlappingDuration returns the overlapping time duration between
// two time intervals [start1, end1] and [start2, end2] where
// start, end parameters are all int64 representing nanoseconds.
func overlappingDuration(start1, end1, start2, end2 int64) time.Duration {
	// assume start1 <= end1 and start2 <= end2
	if end1 < start2 || end2 < start1 {
		return 0
	}

	if start1 < start2 { // choose the later one
		start1 = start2
	}
	if end1 > end2 { // choose the earlier one
		end1 = end2
	}
	return time.Duration(end1 - start1)
}

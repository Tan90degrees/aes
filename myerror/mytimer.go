package myerror

import (
	"fmt"
	"time"
)

type Mytimer struct {
	start time.Time
	dur   time.Duration
}

func (m *Mytimer) Init() {
	m.start = time.Now()
}

func (m *Mytimer) Dur() {
	m.dur = time.Since(m.start)
	fmt.Printf("Time used: %f Second.\n", m.dur.Seconds())
}

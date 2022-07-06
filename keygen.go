package ecdsa_tss

/*
   #cgo CFLAGS:-I${SRCDIR}/ecdsa-tss/include
   #include <stdio.h>
   #include <stdlib.h>
   #include <tss.h>
*/
import "C"
import (
	log "github.com/sirupsen/logrus"
	"time"
)

type Keygen struct {
	inner           *KeygenSimple
	incoming        <-chan string
	outgoing        chan<- string
	pendingOutgoing []string
}

func NewKeygen(i int, t int, n int, incoming <-chan string, outgoing chan<- string) *Keygen {
	kg := NewKeygenSimple(i, t, n)
	return &Keygen{kg, incoming, outgoing, nil}
}

func (k *Keygen) Free() {
	k.inner.Free()
}

func (k *Keygen) Initialize() {
	outgoing := k.inner.Init()
	k.pendingOutgoing = append(k.pendingOutgoing, outgoing...)
}

func (k *Keygen) Output() *string {
	return k.inner.Output()
}

func (k *Keygen) ProcessLoop() {
	var finished bool
	for !finished {
		select {
		case msg, ok := <-k.incoming:
			if ok {
				_, outgoing, _ := k.inner.Handle(msg)
				k.pendingOutgoing = append(k.pendingOutgoing, outgoing...)
				k.trace("keygen_outgoing", len(outgoing))
			}
		case <-time.After(1 * time.Second):
			finished = k.inner.Output() != nil
			k.trace("keygen_finished", finished)
			k.sendOutgoingIfThereIs()
			if finished {
				break
			}
		}
	}
}

func (k *Keygen) sendOutgoingIfThereIs() {
	for len(k.pendingOutgoing) > 0 {
		item := k.pendingOutgoing[0]
		k.pendingOutgoing = k.pendingOutgoing[1:]
		k.trace("sending outgoing", item[:50])
		k.outgoing <- item
	}
}

func (k *Keygen) trace(funcName string, result interface{}) {
	log.WithFields(log.Fields{
		"participant": k.inner.i,
		"funcName":    funcName,
		"result":      result,
	}).Trace("statusCheck")
}

package ecdsa_tss

/*
   #cgo CFLAGS:-I${SRCDIR}/ecdsa-tss/include
   #include <stdio.h>
   #include <stdlib.h>
   #include <tss.h>
*/
import (
	log "github.com/sirupsen/logrus"
	"time"
)

type OfflineStage struct {
	inner           *OfflineStageSimple
	incoming        <-chan string
	outgoing        chan<- string
	pendingOutgoing []string
}

func NewOfflineStage(msgHash string, i int, sL []int, n int, localKey string, incoming <-chan string, outgoing chan<- string) *OfflineStage {
	inner := NewOfflineStageSimple(msgHash, i, sL, n, localKey)
	// void* new_sign(const char* msg_hash, int i, int n, const char* local_key);
	return &OfflineStage{inner, incoming, outgoing, nil}
}

func (k *OfflineStage) Free() {
	k.inner.Free()
}

func (k *OfflineStage) Initialize() {
	outgoing := k.inner.Init()
	k.pendingOutgoing = append(k.pendingOutgoing, outgoing...)
}

func (k *OfflineStage) Output() *SignManual {
	return k.inner.Output()
}

func (k *OfflineStage) ProcessLoop() {
	var finished bool
	for !finished {
		select {
		case msg, ok := <-k.incoming:
			if ok {
				_, outgoing, _ := k.inner.Handle(msg)
				k.pendingOutgoing = append(k.pendingOutgoing, outgoing...)
				k.trace("offline_pending_outgoing", len(k.pendingOutgoing))
			}
		case <-time.After(1 * time.Second):
			finished := k.inner.Output() != nil
			k.trace("offline_finished", finished)
			k.sendOutgoingIfThereIs()
			if finished {
				break
			}
		}
	}
}

func (k *OfflineStage) sendOutgoingIfThereIs() {
	for len(k.pendingOutgoing) > 0 {
		item := k.pendingOutgoing[0]
		k.pendingOutgoing = k.pendingOutgoing[1:]
		k.trace("sending outgoing", item[:50])
		k.outgoing <- item
		k.trace("sent outgoing", item[:50])
	}
}

func (k *OfflineStage) trace(funcName string, result interface{}) {
	log.WithFields(log.Fields{
		"participant": k.inner.i,
		"funcName":    funcName,
		"result":      result,
	}).Trace("statusCheck")
}


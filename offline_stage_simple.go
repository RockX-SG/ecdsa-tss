package ecdsa_tss

/*
#cgo CFLAGS:-I${SRCDIR}/bls-tss/include
#include <stdio.h>
#include <stdlib.h>
#include <tss.h>
*/
import "C"
import (
	log "github.com/sirupsen/logrus"
	"unsafe"
)

type OfflineStageSimple struct {
	msgHash  string
	i        int
	n        int
	localKey string
	state    unsafe.Pointer
	buffer   unsafe.Pointer
	output   *SignManual
}

func NewOfflineStageSimple(msgHash string, i int, sL []int, n int, localKey string) *OfflineStageSimple {
	cKey := C.CString(localKey)
	defer C.free(unsafe.Pointer(cKey))

	buffer := C.malloc(C.size_t(BufferSize))

	slLen := len(sL)


	//slLen := C.size_t(len(sL))
	indices := C.malloc(C.size_t(slLen * C.sizeof_int))
	defer C.free(indices)
	//sIndices := *(*[]int)(indices)
	//copy(sIndices[:], sL[:])

	//indices := make([]int, slLen)
	indicesS := (*[1 << 30]C.int)(unsafe.Pointer(indices))
	for i, partyI := range sL {
		indicesS[i] = C.int(partyI)
	}

	//indices := make([]C.int, len(sL))
	//for i, partyI := range sL {
	//	indices[i] = C.int(partyI)
	//}
	//C.size_t(len(sL))
	//(*C.int)(unsafe.Pointer(&indices))
	//C.int(len(sL))
	log.Debugf("cKey %v", C.GoString((*C.char)(cKey)))
	state := C.new_offline_stage(C.int(i), (*C.int)(unsafe.Pointer(&indices)), C.int(len(sL)), cKey)

	return &OfflineStageSimple{msgHash, i, n, localKey, state, buffer, nil}
}

func (k *OfflineStageSimple) Free() {
	C.free(k.buffer)
	C.free_offline_stage(k.state)
}

func (k *OfflineStageSimple) Init() []string {
	k.proceedIfNeeded()
	return k.getOutgoing()
}

func (k *OfflineStageSimple) Handle(msg string) (bool, []string, error) {
	k.handleIncoming(msg)
	k.proceedIfNeeded()
	outgoing := k.getOutgoing()
	output := k.finishIfPossible()
	finished := output != nil

	if finished {
		k.output = output
	}

	return finished, outgoing, nil
}

func (k *OfflineStageSimple) Output() *SignManual {
	return k.output
}

func (k *OfflineStageSimple) proceedIfNeeded() {
	res := C.offline_stage_wants_to_proceed(k.state)
	k.trace("offline_stage_wants_to_proceed", res)
	if res == 1 {
		res = C.offline_stage_proceed(k.state)
		k.trace("offline_stage_proceed", res)
	}
}

func (k *OfflineStageSimple) getOutgoing() []string {
	var outgoing []string
	res := C.offline_stage_has_outgoing(k.state)
	k.trace("offline_stage_has_outgoing", res)
	for res > 0 {
		outgoingBytesSize := C.offline_stage_outgoing(k.state, (*C.char)(k.buffer), BufferSize)
		k.trace("offline_stage_outgoing_size", outgoingBytesSize)
		out := C.GoString((*C.char)(k.buffer))
		k.trace("offline_stage_outgoing", out[:50])
		outgoing = append(outgoing, C.GoString((*C.char)(k.buffer)))
		res = C.offline_stage_has_outgoing(k.state)
	}
	return outgoing
}

func (k *OfflineStageSimple) handleIncoming(msg string) {
	k.trace("offline_stage_incoming", msg[:50])
	cText := C.CString(msg)
	defer C.free(unsafe.Pointer(cText))
	C.offline_stage_incoming(k.state, cText)
}

func (k *OfflineStageSimple) finishIfPossible() *SignManual {
	finished := C.offline_stage_is_finished(k.state)
	if finished != 1 {
		return nil
	}
	cHash := C.CString(k.msgHash)
	defer C.free(unsafe.Pointer(cHash))
	res := C.offline_stage_to_sign_manual(k.state, cHash)
	if res != nil {
		return NewSignManual(k.i, k.n, res)
	}
	return nil
}

func (k *OfflineStageSimple) trace(funcName string, result interface{}) {
	log.WithFields(log.Fields{
		"participant": k.i,
		"funcName":    funcName,
		"result":      result,
	}).Trace("statusCheck")
}

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

type SignManual struct {
	i      int
	n      int
	state  unsafe.Pointer
	buffer unsafe.Pointer
	output *string
}

func NewSignManual(i int, n int, state unsafe.Pointer) *SignManual {
	buffer := C.malloc(C.size_t(BufferSize))
	return &SignManual{i, n, state, buffer, nil}
}

func (k *SignManual) Free() {
	C.free(k.buffer)
	C.free(k.buffer)
	C.free_sign_manual(k.state)
}

func (k *SignManual) GetPartialSignature() *string {
	res := C.sign_manual_get_partial_signature(k.state, (*C.char)(k.buffer), BufferSize)
	k.trace("sign_manual_get_partial_signature", res)

	if res > 0 {
		out := C.GoString((*C.char)(k.buffer))
		return &out
	}
	return nil
}

func (k *SignManual) Complete(partialSigs []string) *string {
	var sigVec string
	for i, sig := range partialSigs {
		if i > 0 {
			sigVec = sigVec + ","
		}
		sigVec = sigVec + sig
	}
	sigVec = "[" + sigVec + "]"
	sigVecBytes := []byte(sigVec)
	copy((*[1<<24]byte)(k.buffer)[:], sigVecBytes[:])
	res := C.sign_manual_complete(k.state, (*C.char)(k.buffer), BufferSize)
	k.trace("sign_manual_complete", res)
	if res > 0 {
		out := C.GoString((*C.char)(k.buffer))
		return &out
	}
	return nil
}

func (k *SignManual) trace(funcName string, result interface{}) {
	log.WithFields(log.Fields{
		"participant": k.i,
		"funcName":    funcName,
		"result":      result,
	}).Trace("statusCheck")
}


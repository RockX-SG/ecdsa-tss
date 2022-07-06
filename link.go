package ecdsa_tss
/*
#cgo LDFLAGS:-lecdsa_tss -lgmp -lm -ldl
#cgo windows,amd64 LDFLAGS: -lws2_32 -luserenv -lbcrypt
#cgo linux,amd64 LDFLAGS:-L${SRCDIR}/ecdsa-tss/lib/linux/amd64 -L/usr/lib/x86_64-linux-gnu
#cgo linux,arm64 LDFLAGS:-L${SRCDIR}/ecdsa-tss/lib/linux/arm64
#cgo darwin,amd64 LDFLAGS:-L${SRCDIR}/ecdsa-tss/lib/darwin/amd64
#cgo darwin,arm64 LDFLAGS:-L${SRCDIR}/ecdsa-tss/lib/darwin/arm64
#cgo windows,amd64 LDFLAGS:-L${SRCDIR}/ecdsa-tss/lib/windows/amd64
*/
import "C"
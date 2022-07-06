package main

import "C"
import (
	"encoding/json"
	"fmt"
	tss "github.com/RockX-SG/ecdsa-tss"
	log "github.com/sirupsen/logrus"
	"os"
	"sort"
	"sync"
	"time"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})

	//Set log output to standard output (default output is stderr, standard error)
	//Log message output can be any io.writer type
	log.SetOutput(os.Stdout)

	log.SetLevel(log.TraceLevel)
}

func main() {

	t := 1
	n := 3
	var (
		ins       []chan string
		outs      []chan string
		kMachines []*tss.Keygen
		sMachines []*tss.OfflineStage
		buffer    tss.PMArray
		bufferMu  sync.Mutex
	)

	for i := 1; i < n+1; i++ {
		in := make(chan string, n)
		out := make(chan string, n)
		keygen := tss.NewKeygen(i, t, n, in, out)
		ins = append(ins, in)
		outs = append(outs, out)
		kMachines = append(kMachines, keygen)
	}

	defer func(machines []*tss.Keygen) {
		for _, machine := range machines {
			machine.Free()
		}
	}(kMachines)
	addToBuffer := func(str string) {
		bufferMu.Lock()
		defer bufferMu.Unlock()
		msg := tss.ProtocolMessage{}
		if err := json.Unmarshal([]byte(str), &msg); err != nil {
			fmt.Printf("error: %v\n", err)
		} else {
			buffer = append(buffer, msg)
		}
	}
	go func(i1 chan<- string, i2 chan<- string, i3 chan<- string) {
		send := func(msg *tss.ProtocolMessage) {

			if str, err := json.Marshal(msg); err != nil {
				fmt.Printf("error: %v\n", err)
			} else {
				log.Debugf("sender: %v, receiver: %v", msg.Sender, msg.Receiver)

				if msg.Receiver == nil {
					log.Debug("Receiver is null")
					if msg.Sender != 1 {
						log.Debug("sending to 1")
						i1 <- string(str)
						log.Debug("sent to 1")
					}
					if msg.Sender != 2 {
						log.Debug("sending to 2")
						i2 <- string(str)
						log.Debug("sent to 2")
					}
					if msg.Sender != 3 {
						log.Debug("sending to 3")
						i3 <- string(str)
						log.Debug("sent to 3")
					}
				} else {
					rcv := msg.Receiver.(float64)
					switch int(rcv) {
					case 1:
						log.Debug("sending to 1")
						i1 <- string(str)
						log.Debug("sent to 1")
					case 2:
						log.Debug("sending to 2")
						i2 <- string(str)
						log.Debug("sent to 2")
					case 3:
						log.Debug("sending to 3")
						i3 <- string(str)
						log.Debug("sent to 3")
					}
				}

			}

		}
		for {
			select {
			case <-time.After(3 * time.Second):
				log.Debug("trying to send")
				if len(buffer) > 0 {
					if bufferMu.TryLock() {
						log.Debugf("buffer has %v items", len(buffer))
						sort.Sort(buffer)

						send(&buffer[0])
						buffer = buffer[1:]
						bufferMu.Unlock()
					} else {
						log.Debug("failed to acquire lock")
					}
				} else {
					log.Debug("buffer is empty")
				}
			}
		}
	}(ins[0], ins[1], ins[2])

	go func(o1 <-chan string, o2 <-chan string, o3 <-chan string) {

		for {
			select {
			case str, ok := <-o1:
				if ok {
					log.Debugf("sending from o1")
					addToBuffer(str)
				} else {
					log.Error("sending from o1")
				}
			case str, ok := <-o2:
				if ok {
					log.Debugf("sending from o2")
					addToBuffer(str)
				} else {
					log.Error("sending from o2")
				}
			case str, ok := <-o3:
				if ok {
					log.Debugf("sending from o3")
					addToBuffer(str)
				} else {
					log.Error("sending from o3")
				}
			}
		}
	}(outs[0], outs[1], outs[2])
	sink := func(ch <-chan string) {
		for {
			select {
			case <-ch:
				log.Debug("Ignoring msg")
			}
		}
	}

	log.Debug("Starting keygen")
	go kMachines[0].ProcessLoop()
	go kMachines[1].ProcessLoop()
	go kMachines[2].ProcessLoop()

	kMachines[0].Initialize()
	kMachines[1].Initialize()
	kMachines[2].Initialize()
	log.Debug("KeygenSimple started")

	var allFinished bool
	for !allFinished {
		select {
		case <-time.After(5 * time.Second):
			allFinished = true
			for _, machine := range kMachines {
				allFinished = allFinished && machine.Output() != nil
			}
			log.Tracef("keygen allFinished: %v\n", allFinished)
			if allFinished {
				break
			}
		}
	}
	log.Debug("KeygenSimple completed")
	for _, machine := range kMachines {
		log.WithFields(log.Fields{
			"result": *machine.Output(),
		}).Trace("keygen result")
	}

	msgHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 * "a"

	sL := []int{1, 2}
	for _, partyI := range sL {
		sign := tss.NewOfflineStage(msgHash, partyI, sL, len(sL), *kMachines[partyI-1].Output(), ins[partyI-1], outs[partyI-1])
		sMachines = append(sMachines, sign)
	}

	defer func(machines []*tss.OfflineStage) {
		for _, machine := range machines {
			machine.Free()
		}
	}(sMachines)

	log.Debug("Start signing")
	go sMachines[0].ProcessLoop()
	time.Sleep(300 * time.Millisecond)
	go sMachines[1].ProcessLoop()
	go sink(ins[2])

	sMachines[0].Initialize()
	sMachines[1].Initialize()
	//sMachines[2].Initialize()
	log.Debug("Signing started")

	allFinished = false
	for !allFinished {
		select {
		case <-time.After(5 * time.Second):
			allFinished = true
			for _, machine := range sMachines {
				allFinished = allFinished && machine.Output() != nil
			}
			log.Tracef("sign allFinished: %v\n", allFinished)
			if allFinished {
				break
			}
		}
	}
	pSigs := make([]string, 2)
	sms := make([]*tss.SignManual, 2)
	sms[0] = sMachines[0].Output()
	sms[1] = sMachines[1].Output()
	pSigs[0]=*sms[0].GetPartialSignature()
	pSigs[1]=*sms[1].GetPartialSignature()

	sig := sms[0].Complete(pSigs[1:])

	if sig != nil {
		var signature tss.Signature
		err := json.Unmarshal([]byte(*sig), &signature)
		if err != nil {
			log.WithError(err).Error("failed to decode signature")
		}
		log.Debugf("Sig is %v", signature)
		log.Debug("Sig failed")
	}else {

	}
	//sm := sMachines[0].Output()
	//pSig := sm.GetPartialSignature()
	//log.Debug("Signing completed")
	//log.Debugf("pSig is %v", *pSig)
	//log.Infof("msgHash is: %v\n", msgHash)
	//log.Infof("signature is: %v\n", *sMachines[1].Output())

}

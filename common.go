package ecdsa_tss

const BufferSize = 1_048_576

type ProtocolMessage struct {
	Sender   int `json:"sender"`
	Receiver interface{} `json:"receiver"`
	Body     struct {
		Round1 interface{} `json:"Round1,omitempty"`
		Round2 interface{} `json:"Round2,omitempty"`
		Round3 interface{} `json:"Round3,omitempty"`
		Round4 interface{} `json:"Round4,omitempty"`
		M1     interface{} `json:"M1,omitempty"`
		M2     interface{} `json:"M2,omitempty"`
		M3     interface{} `json:"M3,omitempty"`
		M4     interface{} `json:"M4,omitempty"`
		M5     interface{} `json:"M5,omitempty"`
		M6     interface{} `json:"M6,omitempty"`
	} `json:"body"`
}

func (m ProtocolMessage) getRound() int {
	if m.Body.Round1 != nil {
		return 1
	} else if m.Body.Round2 != nil {
		return 2
	} else if m.Body.Round3 != nil {
		return 3
	} else if m.Body.Round4 != nil {
		return 4
	} else if m.Body.M1 != nil {
		return 11
	} else if m.Body.M2 != nil {
		return 12
	} else if m.Body.M3 != nil {
		return 13
	} else if m.Body.M4 != nil {
		return 14
	} else if m.Body.M5 != nil {
		return 15
	} else if m.Body.M6 != nil {
		return 16
	}

	return 99
}

type PMArray []ProtocolMessage

func (a PMArray) Len() int           { return len(a) }
func (a PMArray) Less(i, j int) bool { return a[i].getRound() < a[j].getRound() }
func (a PMArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type Signature struct {
	R struct {
		Curve  string `json:"curve"`
		Scalar []int  `json:"scalar"`
	} `json:"r"`
	S struct {
		Curve  string `json:"curve"`
		Scalar []int  `json:"scalar"`
	} `json:"s"`
	Recid int `json:"recid"`
}
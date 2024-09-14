package ike

import (
	"fmt"
	"io"
	stdlog "log"
	"net"

	"github.com/b1gcat/cryptobox/ike/protocol"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/log"
)

// Message carries the ike packet
type Message struct {
	IkeHeader             *protocol.IkeHeader
	Payloads              *protocol.Payloads
	LocalAddr, RemoteAddr net.Addr

	Data   []byte      // used to carry raw bytes
	Params interface{} // used to carry the parsed/source structure
}

// DecodeHeader decodes the ike header and replaces the IkeHeader member
func (msg *Message) DecodeHeader(b []byte) (err error) {
	msg.IkeHeader, err = protocol.DecodeIkeHeader(b)
	return
}

// DecodePayloads decodes & replaces the payloads member with list of decoded payloads
func (msg *Message) DecodePayloads(b []byte, nextPayload protocol.PayloadType, log log.Logger) (err error) {
	if msg.Payloads, err = protocol.DecodePayloads(b, nextPayload); err != nil {
		return
	}
	if protocol.PacketLog {
		stdlog.Println("RX:" + spew.Sprintf("%#v", msg))
	}
	log.Log("RX", fmt.Sprintf("[%d] %s%s", msg.IkeHeader.MsgID, msg.IkeHeader.ExchangeType, msg.IkeHeader.Flags),
		"payloads", *msg.Payloads)
	return
}

// DecodeMessage decodes an keeps the message buffer for later decryption
func DecodeMessage(b []byte, log log.Logger) (msg *Message, err error) {

	msg = &Message{}
	if err = msg.DecodeHeader(b); err != nil {
		return
	}
	if len(b) < int(msg.IkeHeader.MsgLength) {
		err = io.ErrShortBuffer
		return
	}

	if msg.IkeHeader.SpiR.String() == "0x0000000000000000" {
		err = fmt.Errorf("ignore first packet")
		return
	}

	// further decode
	pld := b[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength]
	if err = msg.DecodePayloads(pld, msg.IkeHeader.NextPayload, log); err != nil {
		return
	}
	// save for later
	msg.Data = b
	return
}

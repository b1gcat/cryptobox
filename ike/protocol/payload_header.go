package protocol

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/b1gcat/cryptobox/ike/packets"
	"github.com/pkg/errors"
)

func (h *PayloadHeader) NextPayloadType() PayloadType {
	return h.NextPayload
}

func (h *PayloadHeader) Header() *PayloadHeader {
	return h
}

func (h *PayloadHeader) Decode(b []byte) error {
	if len(b) < 4 {
		return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Packet Too short : %d", len(b)))
	}
	pt, _ := packets.ReadB8(b, 0)
	h.NextPayload = PayloadType(pt)
	if c, _ := packets.ReadB8(b, 1); c&0x80 == 1 {
		h.IsCritical = true
	}
	h.PayloadLength, _ = packets.ReadB16(b, 2)
	if PacketLog {
		log.Printf("Payload Header: %+v from \n%s", *h, hex.Dump(b))
	}
	return nil
}

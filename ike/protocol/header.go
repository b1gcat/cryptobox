package protocol

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/b1gcat/cryptobox/ike/packets"
	"github.com/pkg/errors"
)

func DecodeIkeHeader(b []byte) (h *IkeHeader, err error) {
	h = &IkeHeader{}
	if len(b) < IKE_HEADER_LEN {
		return nil, errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Packet Too short : %d", len(b)))
	}
	if len(b) > MAX_IKE_MESSAGE_LEN {
		return nil, errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Packet Too large : %d", len(b)))
	}
	h.SpiI = append([]byte{}, b[:8]...)
	h.SpiR = append([]byte{}, b[8:16]...)
	pt, _ := packets.ReadB8(b, 16)
	h.NextPayload = PayloadType(pt)
	ver, _ := packets.ReadB8(b, 16+1)
	h.MajorVersion = ver >> 4
	h.MinorVersion = ver & 0x0f
	et, _ := packets.ReadB8(b, 16+2)
	h.ExchangeType = IkeExchangeType(et)
	flags, _ := packets.ReadB8(b, 16+3)
	h.Flags = IkeFlags(flags)
	h.MsgID, _ = packets.ReadB32(b, 16+4)
	h.MsgLength, _ = packets.ReadB32(b, 16+8)
	if h.MsgLength < IKE_HEADER_LEN {
		return nil, errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Bad Message Length in header : %d", h.MsgLength))
	}
	if h.MsgLength > MAX_IKE_MESSAGE_LEN {
		return nil, errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Bad Message Length in header : %d", h.MsgLength))
	}
	if PacketLog {
		log.Printf("Ike Header: %+v from \n%s", *h, hex.Dump(b[:IKE_HEADER_LEN]))
	}
	return
}

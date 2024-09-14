package protocol

import (
	"fmt"

	"github.com/b1gcat/cryptobox/ike/packets"
	"github.com/pkg/errors"
)

//   Transform Substructure

func decodeAttribute(b []byte) (attr *TransformAttribute, used int, err error) {
	if len(b) < MIN_LEN_ATTRIBUTE {
		err = errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("attribute too small %d < %d", len(b), MIN_LEN_ATTRIBUTE))
		return
	}

	at, _ := packets.ReadB16(b, 0)
	alen, _ := packets.ReadB16(b, 2)
	attr = &TransformAttribute{
		Type:  AttributeType(at & 0x7fff),
		Value: alen,
	}
	used = 4
	return
}

func decodeTransform(b []byte) (trans *SaTransform, used int, err error) {
	if len(b) < MIN_LEN_TRANSFORM {
		err = errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("transform too small %d < %d", len(b), MIN_LEN_TRANSFORM))
		return
	}
	trans = &SaTransform{}
	if last, _ := packets.ReadB8(b, 0); last == 0 {
		trans.IsLast = true
	}
	trLength, _ := packets.ReadB16(b, 2)
	if len(b) < int(trLength) {
		err = errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("transform too small %d < %d", len(b), int(trLength)))
		return
	}
	if int(trLength) < MIN_LEN_TRANSFORM {
		err = errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("transform too small %d < %d", int(trLength), MIN_LEN_TRANSFORM))
		return
	}
	trType, _ := packets.ReadB8(b, 4)
	trans.Transform.Type = TransformType(trType)
	trans.Transform.TransformId, _ = packets.ReadB16(b, 6)
	// variable parts
	b = b[MIN_LEN_TRANSFORM:int(trLength)]
	attrs := make(map[AttributeType]*TransformAttribute)
	for len(b) > 0 {
		attr, attrUsed, attrErr := decodeAttribute(b)
		if attrErr != nil {
			err = attrErr
			return
		}
		b = b[attrUsed:]
		attrs[attr.Type] = attr
	}
	if at, ok := attrs[ATTRIBUTE_TYPE_KEY_LENGTH]; ok {
		trans.KeyLength = at.Value
	}
	used = int(trLength)
	trans.Atrrs = attrs
	return
}

func (tr *SaTransform) IsEqual(other *SaTransform) bool {
	if tr == nil || other == nil {
		return false
	}
	if tr.KeyLength != other.KeyLength {
		return false
	}
	if tr.Transform.Type != other.Transform.Type {
		return false
	}
	if tr.Transform.TransformId != other.Transform.TransformId {
		return false
	}
	return true
}

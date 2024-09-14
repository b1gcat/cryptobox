package packets

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
)

func ReadB64(b []byte, offset int) (uint64, error) {
	if len(b) < 8+offset {
		return 0, io.EOF
	}
	return binary.BigEndian.Uint64(b[offset : offset+8]), nil
}
func ReadB32(b []byte, offset int) (uint32, error) {
	if len(b) < 4+offset {
		return 0, io.EOF
	}
	return binary.BigEndian.Uint32(b[offset : offset+4]), nil
}
func ReadB24(b []byte, offset int) (uint32, error) {
	if len(b) < 3+offset {
		return 0, io.EOF
	}
	b = b[offset:]
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
}
func ReadB16(b []byte, offset int) (uint16, error) {
	if len(b) < 2+offset {
		return 0, io.EOF
	}
	return binary.BigEndian.Uint16(b[offset : offset+2]), nil
}
func ReadB8(b []byte, offset int) (uint8, error) {
	if len(b) < 1+offset {
		return 0, io.EOF
	}
	return b[offset], nil
}

func ReadSB32(b []byte, offset int) (int32, error) {
	if len(b) < 4+offset {
		return 0, io.EOF
	}
	return int32(binary.BigEndian.Uint32(b[offset : offset+4])), nil
}

func ReadSlice(b []byte, off int, lim int, delim byte) (line []byte, err error) {
	i := bytes.IndexByte(b[off:], delim)
	end := off + i
	if i < 0 {
		end = len(b)
		err = io.EOF
	}
	line = b[off:end]
	return line, err
}

func WriteB64(b []byte, offset int, v uint64) error {
	if len(b) < 8+offset {
		return io.EOF
	}
	binary.BigEndian.PutUint64(b[offset:offset+8], v)
	return nil
}
func WriteB32(b []byte, offset int, v uint32) error {
	if len(b) < 4+offset {
		return io.EOF
	}
	binary.BigEndian.PutUint32(b[offset:offset+4], v)
	return nil
}
func WriteB24(b []byte, offset int, v uint32) error {
	if len(b) < 3+offset {
		return io.EOF
	}
	b = b[offset : offset+3]
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
	return nil
}
func WriteB16(b []byte, offset int, v uint16) error {
	if len(b) < 2+offset {
		return io.EOF
	}
	binary.BigEndian.PutUint16(b[offset:offset+2], v)
	return nil
}
func WriteB8(b []byte, offset int, v uint8) error {
	if len(b) < offset {
		return io.EOF
	}
	b[offset] = v
	return nil
}

func WriteSB32(b []byte, offset int, v int32) error {
	if len(b) < 4+offset {
		return io.EOF
	}
	binary.BigEndian.PutUint32(b[offset:offset+4], uint32(v))
	return nil
}

//
// misc
//
var (
	// Integer.numberOfTrailingZeros
	// http://stackoverflow.com/questions/5471129/number-of-trailing-zeros
	// http://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightModLookup
	ZerosOnRightModLookup = []int{
		32, 0, 1, 26, 2, 23, 27, 0, 3, 16, 24, 30, 28, 11, 0, 13, 4, 7, 17,
		0, 25, 22, 31, 15, 29, 10, 12, 6, 0, 21, 14, 9, 5, 20, 8, 19, 18,
	}
)

// zeros rightmost bit
func Zrb(n uint32) uint32 {
	return n ^ (n & (-n))
}

// counts number of trailing zeros
func Ntz(i uint32) int {
	return ZerosOnRightModLookup[(i&-i)%37]
}

/*
 * Converts a string of hex to byte array
 */
func Hexit(b string) *bytes.Buffer {
	s := []byte(b)
	temp := []byte{0}
	idx := 0
	var buffer bytes.Buffer
	for idx <= len(s)-2 {
		_, err := hex.Decode(temp, s[idx:idx+2])
		if err == nil {
			buffer.Write(temp)
			idx += 2
		} else {
			idx += 1
		}
	}
	return &buffer
}

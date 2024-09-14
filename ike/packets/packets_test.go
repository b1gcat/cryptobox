package packets

import (
	"fmt"
	"testing"
)

func TestNtz(t *testing.T) {
	if Ntz(0x30) != 4 {
		t.Fail()
	}
	if Zrb(0x30) != 0x20 {
		t.Fail()
	}
}

func ExampleNtz() {
	var versionBitmap = uint32(0xf0)
	s := ""
	for versionBitmap != 0 {
		s += fmt.Sprintf("0x%02x", Ntz(versionBitmap))
		versionBitmap = Zrb(versionBitmap)
		if versionBitmap != 0 {
			s += ", "
		}
	}
	fmt.Println(s)
	// Output:
	// 0x04, 0x05, 0x06, 0x07
}

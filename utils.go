package main

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

func parseAnyDataToBin(data string) (raw []byte, err error) {
	text := strings.TrimSpace(data)
	if isHex(text) {
		raw, err = hex.DecodeString(text)
	} else {
		raw, err = base64.StdEncoding.DecodeString(text)
	}
	return
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

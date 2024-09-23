package main

import (
	"fmt"
	"testing"
)

func Test_handleFlowClassify(t *testing.T) {
	fmt.Println(handleFlowClassify("/Users/b1gcat/Desktop/proj/gosrc/src/github.com/b1gcat/cryptobox/pcap_sample/testq.pcapng",
		func(r *flowResult) {
			fmt.Println(r)
		}))

}

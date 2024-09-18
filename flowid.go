package main

import (
	"fmt"
	"runtime"
	"strconv"

	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"github.com/b1gcat/cryptobox/ike"
	"github.com/b1gcat/cryptobox/ike/protocol"
	"github.com/b1gcat/cryptobox/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/text/encoding/simplifiedchinese"

	"github.com/go-kit/log"
)

func showErrEx(w fyne.Window, err error) {
	if runtime.GOOS == "windows" {
		errStr, err := simplifiedchinese.GB18030.NewDecoder().String(err.Error())
		if err == nil {
			dialog.ShowError(fmt.Errorf("%v", errStr), w)
			return
		}
	}
	dialog.ShowError(err, w)
}

// https://www.winpcap.org/install/
func flowClassify(_ fyne.Window) {
	w := appWin.NewWindow("报文分析")
	size := fyne.Size{Width: 800, Height: 250}

	w.Resize(size)
	w.CenterOnScreen()
	w.Show()

	var pktPath string
	var pktBtn *widget.Button
	pktBtn = widget.NewButton("导入数据包", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}

			defer reader.Close()

			pktPath = reader.URI().Path()
			pktBtn.SetText(pktPath)
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".pcap", ".cap", ".pcapng"}))
		fd.Show()
	})

	devices, err := pcap.FindAllDevs()
	if err != nil {
		showErrEx(w, err)
		return
	}
	dev := widget.NewSelectEntry([]string{})
	v4 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("网卡列表"), layout.NewSpacer(), dev)
	devs := make([]string, 0)
	for _, d := range devices {
		devs = append(devs, d.Name)
	}
	dev.SetOptions(devs)
	if len(devs) != 0 {
		dev.SetText(devs[0])
	}
	dev.Hide()
	capLive := widget.NewCheck("启用网卡抓包模式", func(changed bool) {
		if changed {
			pktBtn.Hide()
			dev.Show()
			pktPath = "any"
		} else {
			dev.Hide()
			pktBtn.Show()
		}
	})

	result := widget.NewMultiLineEntry()
	result.SetMinRowsVisible(15)

	var analysis *widget.Button
	analysis = widget.NewButton("分析", func() {

		analysis.Disable()
		defer analysis.Enable()

		if err := handleFlowClassify(pktPath, func(r *flowResult) {
			result.Append(fmt.Sprintf("[+] %v: %v/%v<->%v\n",
				r.Version, r.Cybersuite, r.Src, r.Dst))
		}); err != nil {
			showErrEx(w, err)
		}

	})

	v3 := container.NewVBox(capLive, v4, pktBtn, analysis, result)

	content := container.NewVBox(v3)
	w.SetContent(content)
}

type flowResult struct {
	Version    string
	Cybersuite string
	Src, Dst   string
}

func handleFlowClassify(pcapFile string, cb func(*flowResult)) error {
	var handle *pcap.Handle
	var err error

	if _, err = os.Stat(pcapFile); err != nil {
		handle, err = pcap.OpenLive(pcapFile, 1600, true, pcap.BlockForever)
	} else {
		handle, err = pcap.OpenOffline(pcapFile)
	}
	if err != nil {
		return err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for packet := range packetSource {
		if packet.ApplicationLayer() == nil ||
			packet.NetworkLayer() == nil ||
			packet.TransportLayer() == nil {
			continue
		}

		switch packet.TransportLayer().LayerType() {
		case layers.LayerTypeTCP:
			sh := tlsx.GetServerHello(packet)
			if sh == nil {
				continue
			}

			if _, ok := tlsx.VersionReg[tlsx.Version(sh.Vers)]; !ok {
				continue
			}

			cb(&flowResult{
				Version:    tlsx.Version(sh.Vers).String(),
				Cybersuite: tlsx.CipherSuite(sh.CipherSuite).String(),
				Src: packet.NetworkLayer().NetworkFlow().Reverse().Src().String() + ":" +
					packet.TransportLayer().TransportFlow().Reverse().Src().String(),
				Dst: packet.NetworkLayer().NetworkFlow().Reverse().Dst().String() + ":" +
					packet.TransportLayer().TransportFlow().Reverse().Dst().String(),
			})
		case layers.LayerTypeUDP:
			if packet.TransportLayer().TransportFlow().Dst().String() == "4500" ||
				packet.TransportLayer().TransportFlow().Dst().String() == "500" ||
				packet.TransportLayer().TransportFlow().Src().String() == "4500" ||
				packet.TransportLayer().TransportFlow().Src().String() == "500" {
				t, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)

				asymmetric := "?"
				hash := "?"
				enc := "?"
				authMethold := "?"
				isakmp, err := ike.DecodeMessage(t.LayerPayload(),
					log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr)))
				if err == nil {
					sa := isakmp.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)

					for _, prop := range sa.Proposals {
						for _, tr := range prop.Transforms {
							if tr.Atrrs != nil {
								for _, attr := range tr.Atrrs {
									switch attr.Type {
									case 20:
										asymmetric = strconv.Itoa(int(attr.Value))
										if attr.Value == 2 {
											asymmetric = "SM2"
										}
									case 2:
										hash = strconv.Itoa(int(attr.Value))
										if attr.Value == 20 {
											hash = "SM3"
										}
									case 1:
										enc = strconv.Itoa(int(attr.Value))
										if attr.Value == 129 {
											enc = "SM4"
										}
									case 3:
										authMethold = strconv.Itoa(int(attr.Value))
										if attr.Value == 10 {
											authMethold = "公钥数字信封"
										}
									}
								}
							}
						}
					}
					cb(&flowResult{
						Version: "IPsec",
						Cybersuite: fmt.Sprintf("%v-%v-%v-%v",
							asymmetric, hash, enc, authMethold),
						Src: packet.NetworkLayer().NetworkFlow().Reverse().Src().String() + ":" +
							packet.TransportLayer().TransportFlow().Reverse().Src().String(),
						Dst: packet.NetworkLayer().NetworkFlow().Reverse().Dst().String() + ":" +
							packet.TransportLayer().TransportFlow().Reverse().Dst().String(),
					})
				}
			}
		}

	}
	return nil
}

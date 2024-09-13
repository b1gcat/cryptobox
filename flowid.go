package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"github.com/b1gcat/cryptobox/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func flowClassify(_ fyne.Window) {
	w := appWin.NewWindow("报文分析")
	size := fyne.Size{Width: 500, Height: 250}

	setIcon(w)

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
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".pcap", ".cap"}))
		fd.Show()
	})

	var analysis *widget.Button
	analysis = widget.NewButton("验证", func() {

		analysis.Disable()
		defer analysis.Enable()

	})

	result := widget.NewMultiLineEntry()
	result.SetMinRowsVisible(15)

	v3 := container.NewVBox(pktBtn, analysis, result)

	content := container.NewVBox(v3)
	w.SetContent(content)
}

type flowResult struct {
	Version    string
	Cybersuite string
	Src, Dst   string
}

func handleFlowClassify(pcapFile string, cb func(*flowResult)) error {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for packet := range packetSource {
		if packet.ApplicationLayer() == nil &&
			packet.NetworkLayer() == nil &&
			packet.TransportLayer() == nil {
			continue
		}

		if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
			sh := tlsx.GetServerHello(packet)
			if sh == nil {
				continue
			}

			if _, ok := tlsx.VersionReg[sh.Vers]; !ok {
				continue
			}

			cb(&flowResult{
				Version:    tlsx.Version(sh.Vers).String(),
				Cybersuite: tlsx.CipherSuite(sh.CipherSuite).String(),
				Src:        packet.NetworkLayer().NetworkFlow().Src().String(),
				Dst:        packet.NetworkLayer().NetworkFlow().Dst().String(),
			})

		}
	}
}

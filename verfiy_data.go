package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/validation"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/emmansun/gmsm/sm2"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func verifyData(_ fyne.Window) {
	w := appWin.NewWindow("SM2公钥验签名")
	size := fyne.Size{Width: 600, Height: 250}

	w.Resize(size)
	w.CenterOnScreen()
	w.Show()

	pub := widget.NewEntry()
	pub.SetText("04abfbfe470afbe7441b7d4067a5d613bd736a596562f9342525cb7ad3b28ce28b93bc3147e8ae678d52b52feab06e075a30cfb317b9503eaeffb0b97b88cb1652")
	pub.Validator = validation.NewRegexp("(?m)(?:0[xX])?[0-9a-fA-F]+", "填写16进制")
	v0 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("公钥(hex)"), layout.NewSpacer(), pub)

	data := widget.NewEntry()
	data.SetText("8a3f6f7f38f5db3a9dac0f2aa9a6580094b66ccde685e763782132f961432aa059")
	data.Validator = validation.NewRegexp("[0-9a-fA-F]+", "填写16进制")
	v1 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("原始数据(hex)"), layout.NewSpacer(), data)

	sign := widget.NewEntry()
	sign.SetText("30450220704c562920bcc0c1d1fca6ac97ace8e415940bbdf0ebc9d99b8a8b5b7b442b21022100819eb64e9c82aa72f41e5b84c8b1d01cc6f50bcce6ab272288fe653739d6a6b7")
	sign.Validator = validation.NewRegexp("[0-9a-fA-F]+", "填写16进制")
	v2 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("签名值(ANS.1 hex)"), layout.NewSpacer(), sign)

	result := widget.NewMultiLineEntry()
	result.SetMinRowsVisible(15)

	//
	var verify *widget.Button
	verify = widget.NewButton("验签", func() {

		verify.Disable()
		defer verify.Enable()

		signData, err := hex.DecodeString(strings.TrimSpace(sign.Text))
		if err != nil {
			result.Append(fmt.Sprintf("签名数据格式错误:%v\n", err.Error()))
			return
		}
		input := cryptobyte.String(signData)
		var inner cryptobyte.String
		var rd, sd []byte
		if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1Integer(&rd) ||
			!inner.ReadASN1Integer(&sd) ||
			!inner.Empty() {
			result.Append(fmt.Sprintf("签名数据格式错误:%v\n", errors.New("invalid ASN.1")))
			return
		}

		r := big.NewInt(0).SetBytes(rd)
		s := big.NewInt(0).SetBytes(sd)

		result.Append(fmt.Sprintf("解析签名r: 0x%v\n", r.Text(16)))
		result.Append(fmt.Sprintf("解析签名s: 0x%v\n", s.Text(16)))

		raw, err := hex.DecodeString(strings.TrimSpace((data.Text)))
		if err != nil {
			result.Append(fmt.Sprintf("解析原始数据错误 %v\n", err.Error()))
			return
		}

		pubKey, err := hex.DecodeString(strings.TrimSpace((pub.Text)))
		if err != nil {
			result.Append(fmt.Sprintf("解析公钥错误 %v\n", err.Error()))
			return
		}

		p, err := sm2.NewPublicKey(pubKey)
		if err != nil {
			result.Append(fmt.Sprintf("解析公钥错误 %v\n", err.Error()))
			return
		}

		result.Append(fmt.Sprintf("验证结果%v\n", sm2.Verify(p, raw, r, s)))

	})

	box := container.NewVBox(v0, v1, v2, verify, result)
	content := container.NewVBox(box)
	w.SetContent(content)
}

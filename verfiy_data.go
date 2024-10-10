package main

import (
	"crypto/ecdsa"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

func verifyData(_ fyne.Window) {
	w := appWin.NewWindow("SM2验签名")
	size := fyne.Size{Width: 600, Height: 250}

	w.Resize(size)
	w.CenterOnScreen()
	w.Show()

	pub := widget.NewEntry()
	pub.SetText("0451d965a06ded69c736744f4fe17f828ebb4c4706f9b31b208213761a487370cedb61d6273099039e1e3eebc5bc65ad40ddb5f3ec91e8930a86db071357444b45")
	v0 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("证书/公钥(hex/base64)"), layout.NewSpacer(), pub)

	data := widget.NewEntry()
	data.SetText("3966456e64586636353477794777503365316175756861525149734552643654383558485a74503538766f3d")
	v1 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("原始数据(hex/base64)"), layout.NewSpacer(), data)

	sign := widget.NewEntry()
	sign.SetText("304502210083f5603f64554f03400307ccb1783c411c8e441b6878e081fcf1c60fee8c501a0220328f92b6c9a4db6a527bf9d116e83a35ff5040a1343beeb166b6971e9204f2f5")
	v2 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("签名值(ANS.1 hex/base64)"), layout.NewSpacer(), sign)

	hash := widget.NewSelectEntry([]string{"None", "SM3", "SM2WithSM3"})
	hash.SetText("SM2WithSM3")
	v3 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("HASH计算方式"), layout.NewSpacer(), hash)

	result := widget.NewMultiLineEntry()
	result.SetMinRowsVisible(15)

	//
	var verify *widget.Button
	verify = widget.NewButton("验签", func() {
		result.SetText("")

		verify.Disable()
		defer verify.Enable()

		signData, err := parseAnyDataToBin(sign.Text)
		if err != nil {
			result.Append(fmt.Sprintf("签名数据格式错误:%v\n", err.Error()))
			return
		}

		pubKeyOrCert, err := parseAnyDataToBin(pub.Text)
		if err != nil {
			result.Append(fmt.Sprintf("解析公钥错误 %v\n", err.Error()))
			return
		}
		x, err := smx509.ParseCertificate(pubKeyOrCert)
		var pub *ecdsa.PublicKey
		if err != nil {
			pub, err = sm2.NewPublicKey(pubKeyOrCert)
			if err != nil {
				result.Append(fmt.Sprintf("解析公钥错误 %v\n", err.Error()))
				return
			}
		} else {
			pub = x.PublicKey.(*ecdsa.PublicKey)
		}

		raw, err := parseAnyDataToBin(data.Text)
		if err != nil {
			result.Append(fmt.Sprintf("解析原始数据错误 %v\n", err.Error()))
			return
		}

		switch hash.Text {
		case "SM3":
			digest := sm3.Sum(raw)
			raw = digest[:]
		case "SM2WithSM3":
			digest, err := sm2.CalculateSM2Hash(pub, raw, []byte("1234567812345678"))
			if err != nil {
				result.Append(fmt.Sprintf("CalculateSM2Hash: %v\n", err.Error()))
				return
			}
			raw = digest
		}

		result.Append(fmt.Sprintf("使用hash算法:%v\n", hash.Text))

		result.Append(fmt.Sprintf("验证结果%v\n", sm2.VerifyASN1(pub, raw[:], signData)))

	})

	box := container.NewVBox(v1, v0, v2, v3, verify, result)
	content := container.NewVBox(box)
	w.SetContent(content)
}

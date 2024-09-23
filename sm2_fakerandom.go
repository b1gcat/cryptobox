package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/validation"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/emmansun/gmsm/sm2"
)

func verifySm2Random(_ fyne.Window) {
	w := appWin.NewWindow("sm2随机数漏洞检查与破解d")
	size := fyne.Size{Width: 600, Height: 500}

	w.Resize(size)
	w.CenterOnScreen()
	w.Show()

	e1 := widget.NewEntry()
	e1.SetText("875817FFC25231A88B68696273AEECE852A10CCDE93C19476482EBA4D4877322")
	e1.Validator = validation.NewRegexp("(?m)(?:0[xX])?[0-9a-fA-F]+", "填写16进制")
	v0 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("挑战值1"), layout.NewSpacer(), e1)

	r1 := widget.NewEntry()
	r1.SetText("1260185C3D7437E6A63F1E18FD810A314A5E27D67884A83F1283D72F1009F699")
	r1.Validator = validation.NewRegexp("(?:0[xX])?[0-9a-fA-F]+", "填写16进制")
	v1 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("r1"), layout.NewSpacer(), r1)

	s1 := widget.NewEntry()
	s1.SetText("0E9F423B578A8707C83C1A0A3982F52D0FF718C2B481966E4D839CD566EE7209")
	s1.Validator = validation.NewRegexp("(?:0[xX])?[0-9a-fA-F]+", "填写16进制")
	v2 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("s1"), layout.NewSpacer(), s1)

	e2 := widget.NewEntry()
	e2.SetText("8FB2B63B9CF9ED7842CC0E0A204B36A3ED5C45936B6148646A26915120F6C7D2")
	e2.Validator = validation.NewRegexp("(?:0[xX])?[0-9a-fA-F]+", "填写16进制")
	v3 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("挑战值2"), layout.NewSpacer(), e2)

	r2 := widget.NewEntry()
	r2.SetText("1ABAB698181BF3B65DA2C2C0AA1D53ECE519609BFAA9D75C18277CDB5C794B49")
	r2.Validator = validation.NewRegexp("(?:0[xX])?[0-9a-fA-F]+", "填写16进制")
	v4 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("r2"), layout.NewSpacer(), r2)

	s2 := widget.NewEntry()
	s2.SetText("EBB541CA42C5CCA5FA1324DDC32D3F352546FE4EECE8034E1D64A2848E2A93B9")
	s2.Validator = validation.NewRegexp("(?:0[xX])?[0-9a-fA-F]+", "填写16进制")
	v5 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("s2"), layout.NewSpacer(), s2)

	result := widget.NewMultiLineEntry()
	result.SetMinRowsVisible(15)

	//
	var crackKey *widget.Button
	crackKey = widget.NewButton("验证k(kG)是否固定", func() {

		crackKey.Disable()
		defer crackKey.Enable()
		result.SetText("")

		param := verifySm2RandomParam{
			r1: strings.TrimSpace(r1.Text),
			r2: strings.TrimSpace(r2.Text),
			e1: strings.TrimSpace(e1.Text),
			e2: strings.TrimSpace(e2.Text),
			s1: strings.TrimSpace(s1.Text),
			s2: strings.TrimSpace(s2.Text),
			w:  w,
		}

		param.crackPrivateKey(result)
	})

	box := container.NewVBox(v0, v1, v2, v3, v4, v5, crackKey, result)
	content := container.NewVBox(box)
	w.SetContent(content)
}

type verifySm2RandomParam struct {
	r1, r2, e1, e2, s1, s2 string
	w                      fyne.Window
}

func (v *verifySm2RandomParam) crackPrivateKey(result *widget.Entry) {
	r1 := big.NewInt(0)
	r1.SetString(v.r1, 16)

	e1 := big.NewInt(0)
	e1.SetString(v.e1, 16)

	s1 := big.NewInt(0)
	s1.SetString(v.s1, 16)

	r2 := big.NewInt(0)
	r2.SetString(v.r2, 16)

	e2 := big.NewInt(0)
	e2.SetString(v.e2, 16)

	s2 := big.NewInt(0)
	s2.SetString(v.s2, 16)

	n := big.NewInt(0)
	n.SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

	a := big.NewInt(0).Mod(big.NewInt(0).Sub(r1, r2), n)
	b := big.NewInt(0).Mod(big.NewInt(0).Sub(e1, e2), n)

	result.Append(fmt.Sprintf("r1-r2 mod n = %v\n", a.Text(16)))
	result.Append(fmt.Sprintf("e1-e2 mod n = %v\n", a.Text(16)))

	if (a.Cmp(b)) != 0 {
		result.Append("因(r1-r2) mod n ≢ (e1-e2) mod n, k值无法判断是否随机,所以无法计算d")
		return
	}

	//d≡[ (r2-r1) * (r2-r1-(s1-s2))-1 ] -1 mod n，
	d := big.NewInt(0).Mod(
		big.NewInt(0).Sub(
			big.NewInt(0).Mul(
				big.NewInt(0).Sub(r2, r1),
				big.NewInt(0).ModInverse(
					big.NewInt(0).Sub(
						big.NewInt(0).Sub(r2, r1),
						big.NewInt(0).Sub(s1, s2)), n)),
			big.NewInt(1)), n)

	result.Append("(r1-r2) ≡ (e1-e2) mod n, 所以k值不随机, 随机数存在问题")
	result.Append(fmt.Sprintf(`
	计算过程:
	e1:0x%v
	r1:0x%v
	s1:0x%v
	e2:0x%v
	r2:0x%v
	s2:0x%v
	n: 0x%v
	d ≡ [ (r2-r1) * (r2-r1-(s1-s2))-1 ] -1 mod n
	d = 0x%v
	`, e1.Text(16), r1.Text(16), s1.Text(16),
		e2.Text(16), r2.Text(16), s2.Text(16),
		n.Text(16), d.Text(16)))
	result.Append("验证d:\n")
	priv, err := sm2.NewPrivateKeyFromInt(d)
	if err != nil {
		result.Append("[x]:" + err.Error())
		return
	}
	message, err := hex.DecodeString(v.e1)
	if err != nil {
		result.Append("[x]: e1不是有效的16进制字符串")
		return
	}

	result.Append(
		fmt.Sprintf("校验e1签名:%v\n",
			sm2.Verify(&priv.PublicKey,
				message, r1, s1)))
}

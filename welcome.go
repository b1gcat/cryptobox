package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/b1gcat/cryptobox/resources"
)

func runWelcome() {
	w := appWin.NewWindow(AppName)
	w.SetTitle(AppName)

	logo := canvas.NewImageFromResource(resources.WelcomePng)
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(256, 256))

	var login *widget.Button
	login = widget.NewButton("快速进入", func() {

		login.Disable()
		defer login.Enable()
		w.Hide()
		ui(w)
	})

	content := container.NewVBox(
		logo,
		login,
		widget.NewLabelWithStyle("\n安正安全网络技术有限公司\n", fyne.TextAlignCenter, fyne.TextStyle{Italic: true}))

	w.SetContent(content)
	w.Show()
}

package main

import (
	"fmt"
	"os/exec"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func ui(w fyne.Window) {

	setIcon(w)
	//环境检查
	var ckEnv *widget.Button
	ckEnv = widget.NewButton("环境校验", func() {
		//初始化
		ckEnv.Disable()
		defer ckEnv.Enable()
		requireSoftware := []string{"hashid", "openssl"}
		for _, soft := range requireSoftware {
			if _, err := exec.LookPath(soft); err != nil {
				dialog.ShowError(err, w)
				return
			}
		}

		dialog.ShowInformation("已安装",
			strings.Join(requireSoftware, ","), w)
	})

	//证书校验
	var verifyCertBtn *widget.Button
	verifyCertBtn = widget.NewButton("校验证书", func() {
		//初始化
		verifyCertBtn.Disable()
		defer verifyCertBtn.Enable()
		verifyCert(w)
	})

	funcList := container.NewVBox(ckEnv, verifyCertBtn)
	v3Center := container.NewCenter(funcList)

	header, footer := makeHeadeFooter(AppName)

	ctnt := container.NewVBox(header, v3Center, footer)
	w.SetContent(ctnt)
}

func makeHeadeFooter(info string) (header *fyne.Container, footer *fyne.Container) {
	title := widget.NewLabel(info)

	header = container.NewCenter(title, layout.NewSpacer())
	copyright := widget.NewLabel(fmt.Sprintf("%s-%s/by b1gcat", AppName, Version))
	footer = container.NewCenter(layout.NewSpacer(), copyright)
	return
}

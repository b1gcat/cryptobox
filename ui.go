package main

import (
	"net/url"
	"os/exec"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func ui() {
	w := appWin.NewWindow(AppName)
	//样式
	w.Resize(fyne.Size{Width: 200, Height: 250})
	//w居中显示
	w.CenterOnScreen()
	//循环运行
	setIcon(w)
	//环境检查
	var ckEnv *widget.Button
	ckEnv = widget.NewButton("环境校验", func() {
		//初始化
		ckEnv.Disable()
		defer ckEnv.Enable()
		requireSoftware := []string{"openssl"}
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

	//证书校验
	var verifyD *widget.Button
	verifyD = widget.NewButton("SM2公钥验签", func() {
		//初始化
		verifyD.Disable()
		defer verifyD.Enable()
		verifyData(w)
	})

	//sm2随机数固定破解私钥
	var crackSM2randomBtn *widget.Button
	crackSM2randomBtn = widget.NewButton("SM2随机数固定破解", func() {
		//初始化
		crackSM2randomBtn.Disable()
		defer crackSM2randomBtn.Enable()
		verifySm2Random(w)
	})

	//hash-identifier
	var hashID *widget.Button
	hashID = widget.NewButton("HASH识别", func() {
		//初始化
		hashID.Disable()
		defer hashID.Enable()
		verifyHashId(w)
	})

	//Flow classify
	var flowid *widget.Button
	flowid = widget.NewButton("报文分析", func() {
		//初始化
		flowid.Disable()
		defer flowid.Enable()
		flowClassify(w)
	})

	//AI LLM
	var aiChat *widget.Button
	aiChat = widget.NewButton("AI评估助手", func() {
		//初始化
		aiChat.Disable()
		defer aiChat.Enable()
		runAIChat(w)
	})

	funcList := container.NewVBox(ckEnv, verifyCertBtn, verifyD,
		crackSM2randomBtn, hashID, flowid, aiChat)

	header, footer := makeHeadeFooter("🌟🌟🌟 " + FullName + " 🌟🌟🌟")

	ctnt := container.NewVBox(header, funcList,
		layout.NewSpacer(),
		layout.NewSpacer(),
		layout.NewSpacer(),
		footer,
		layout.NewSpacer())
	w.SetContent(ctnt)
	w.Show()
}

func makeHeadeFooter(info string) (header *fyne.Container, footer *fyne.Container) {
	title := widget.NewLabel(info)
	title.TextStyle = fyne.TextStyle{Bold: true, Underline: true, Monospace: true}
	header = container.NewCenter(title, layout.NewSpacer())

	verLink, _ := url.Parse("https://github.com/b1gcat/cryptobox")
	footer = container.NewHBox(
		layout.NewSpacer(),
		widget.NewHyperlink(AppName+"/"+Version, verLink),
		layout.NewSpacer(),
	)
	return
}

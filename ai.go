package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/ollama/ollama/api"
)

func runAIChat(_ fyne.Window) {
	w := appWin.NewWindow("AI助手")
	size := fyne.Size{Width: 600, Height: 250}

	w.Resize(size)
	w.CenterOnScreen()
	w.Show()

	result := widget.NewMultiLineEntry()
	result.SetMinRowsVisible(15)

	address := widget.NewEntry()
	address.SetText("localhost:11434")

	model := widget.NewSelectEntry([]string{})
	v1 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("模型"), layout.NewSpacer(), model)

	var client *api.Client
	var connect *widget.Button
	connect = widget.NewButton("连接", func() {
		base, err := url.Parse("http://" + address.Text)
		if err != nil {
			result.Append("[-] " + err.Error() + "\n")
			return
		}

		client = api.NewClient(base, &http.Client{})
		resp, err := client.List(context.Background())
		if err != nil {
			result.Append("[-] " + err.Error() + "\n")
			return
		}

		models := make([]string, 0)
		for _, m := range resp.Models {
			models = append(models, m.Name)
			result.Append("[+]" + m.Name + "\n")
		}

		if len(models) == 0 {
			result.Append("[-]" + "无模型" + "\n")
			return
		}

		model.SetOptions(models)
		model.SetText(models[0])
		connect.Disable()
		defer connect.Enable()

	})

	v0 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("大模型API地址"), connect, address)

	question := widget.NewMultiLineEntry()
	question.SetMinRowsVisible(10)
	question.SetText("你是谁")
	v2 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("问题"), layout.NewSpacer(), question)

	v3 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("回答"), layout.NewSpacer(), result)

	//
	var send *widget.Button
	send = widget.NewButton("发送", func() {
		if client == nil {
			dialog.ShowError(fmt.Errorf("未连接大模型"), w)
			return
		}
		result.Append("[+] 使用模型" + model.Text + "\n")
		err := client.Generate(context.Background(), &api.GenerateRequest{
			Prompt: question.Text,
			Model:  model.Text,
		}, func(cr api.GenerateResponse) error {
			result.Append(cr.Response)
			if cr.Done {
				result.Append("\n[+] 结束原因:" + cr.DoneReason)
			}
			return nil
		})
		if err != nil {
			result.Append("[-] " + err.Error() + "\n")
			return
		}
		send.Disable()
		defer send.Enable()

	})

	box := container.NewVBox(v0, v1, v2, v3, send)
	content := container.NewVBox(box)
	w.SetContent(content)
}

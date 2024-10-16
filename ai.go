package main

import (
	"context"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/langgenius/dify-sdk-go"
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
	address.SetText("http://localhost")
	v0 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("API地址"), layout.NewSpacer(), address)

	key := widget.NewEntry()
	key.SetText("app-gureJ1ADylgxZb9FYV1Y5MNy")

	v1 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("API密钥"), layout.NewSpacer(), key)

	question := widget.NewMultiLineEntry()
	question.SetMinRowsVisible(10)
	question.SetText("介绍商用密码评估")

	v2 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("问题"), layout.NewSpacer(), question)

	v3 := container.NewBorder(layout.NewSpacer(), layout.NewSpacer(),
		widget.NewLabel("回答"), layout.NewSpacer(), result)

	//
	var send *widget.Button
	send = widget.NewButton("发送", func() {
		send.Disable()
		defer send.Enable()

		var (
			ctx = context.Background()
			c   = dify.NewClient(address.Text, key.Text)

			req = &dify.ChatMessageRequest{
				Query: question.Text,
				User:  "api-user",
			}

			ch  chan dify.ChatMessageStreamChannelResponse
			err error
		)

		if ch, err = c.Api().ChatMessagesStream(ctx, req); err != nil {
			return
		}

		for {
			select {
			case <-ctx.Done():
				return
			case streamData, isOpen := <-ch:
				if err = streamData.Err; err != nil {
					result.Append("\n" + err.Error() + "\n")
					return
				}
				if !isOpen {
					result.Append("\nEnd\n")
					return
				}

				result.Append(streamData.Answer)
			}
		}

	})

	box := container.NewVBox(v0, v1, v2, v3, send)
	content := container.NewVBox(box)
	w.SetContent(content)
}

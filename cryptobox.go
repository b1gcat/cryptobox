package main

import (
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	_ "github.com/lengzhao/font/autoload"
)

var (
	Version = "1.0"
	AppName = "demo"
	AppID   = "com.demo"
)

var (
	appWin = app.NewWithID(AppID)
)

func main() {
	w := appWin.NewWindow(AppName)
	ui(w)

	//样式
	w.Resize(fyne.Size{Width: 370, Height: 400})
	//w居中显示
	w.CenterOnScreen()
	//循环运行
	w.ShowAndRun()

}

func setIcon(w fyne.Window) {
	icon, err := fyne.LoadResourceFromPath(filepath.Join("resources", "crypto.png"))
	if err == nil {
		w.SetIcon(icon)
	}
}

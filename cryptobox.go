package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/cmd/fyne_demo/data"

	_ "github.com/lengzhao/font/autoload"
)

var (
	Version  = "1.0"
	AppName  = "demo"
	AppID    = "com.demo"
	FullName = "Commercial Cryptography Testing"
)

var (
	appWin = app.NewWithID(AppID)
)

func main() {
	appWin.SetIcon(data.FyneLogoTransparent)
	runWelcome()
	appWin.Run()
}

func setIcon(w fyne.Window) {
	//w.SetIcon(resources.IconPng)
}

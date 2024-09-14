package main

import (
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/cmd/fyne_demo/data"

	_ "github.com/lengzhao/font/autoload"
)

var (
	Version  = "1.0"
	AppName  = "demo"
	AppID    = "com.demo"
	FullName = "AZ. Commercial Cryptography Testing"
)

var (
	appWin = app.NewWithID(AppID)
)

func main() {
	appWin.SetIcon(data.FyneLogoTransparent)
	runWelcome()
	appWin.Run()
}

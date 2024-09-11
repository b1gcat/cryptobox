package main

import (
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

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
	runWelcome()
	appWin.Run()
}

func setIcon(w fyne.Window) {
	icon, err := fyne.LoadResourceFromPath(filepath.Join("resources", "crypto.png"))
	if err == nil {
		w.SetIcon(icon)
	}
}

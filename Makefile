#make OS=window
#make

Version=v1.0.$(shell git log -1 --format=%H |head -c 8)
AppName=CryptoBox
AppID=com.azcp
AppSuffix=

ldFlag=-s -w -X main.Version=$(Version)  -X main.AppName=$(AppName) -X main.AppID=$(AppID)

all:win
	go build -ldflags "$(ldFlag)" -o dist/$(AppName)$(AppSuffix)

win:
	CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -ldflags "$(ldFlag)" -o dist/$(AppName).exe 
	

#make OS=window
#make

Version=v1.0.$(shell git log -1 --format=%H |head -c 8)
AppName=AZCCTP
AppID=com.azcp

ldFlag=-s -w -X main.Version=$(Version)  -X main.AppName=$(AppName) -X main.AppID=$(AppID)

all:win darwin
	
darwin:
	CGO_ENABLED=1 go build -ldflags "$(ldFlag)" -o dist/$(AppName)
win: icon_win
	CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -ldflags "$(ldFlag) -H=windowsgui" -o dist/$(AppName).exe 
	rm -rf *.syso
	
icon_win:
	rsrc -ico resources/crypto.ico \
		-manifest resources/cryptobox.exe.manifest -o cryptobox.syso

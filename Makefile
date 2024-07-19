#make OS=window
#make

Version=v1.0.$(shell git log -1 --format=%H |head -c 8)
AppName=CryptoBox
AppID=com.azcp
AppSuffix=

ldFlag=-s -w -X main.Version=$(Version)  -X main.AppName=$(AppName) -X main.AppID=$(AppID)

ifeq ($(OS),window)
	AppSuffix=.exe
endif

all:
	go build -ldflags "$(ldFlag)" -o $(AppName)$(AppSuffix)
	

Version=v1.0.$(shell git log -1 --format=%H |head -c 8)
AppName=cryptobox
AppID=com.azcp

ldFlag=-s -w -X main.Version=$(Version)  -X main.AppName=$(AppName) -X main.AppName=$(AppID)

all:
	go build -ldflags "$(ldFlag)" -o $(AppName)
	

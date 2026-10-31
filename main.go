package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed packaging/n-orm-proxy.png
var appIcon []byte

func main() {
	app := NewApp()
	err := wails.Run(&options.App{Title: "NAT-on-steroids", Linux: &linux.Options{Icon: appIcon, ProgramName: "nat-on-steroids", WebviewGpuPolicy: linux.WebviewGpuPolicyNever}, Width: 1040, Height: 780, MinWidth: 420, MinHeight: 480, BackgroundColour: options.NewRGBA(12, 20, 37, 255), AssetServer: &assetserver.Options{Assets: assets}, OnStartup: app.startup, OnShutdown: app.shutdown, Bind: []interface{}{app}})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

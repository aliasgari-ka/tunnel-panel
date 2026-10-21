package main

import (
	"embed"
	"io/fs"
)

//go:embed web
var webFS embed.FS

//go:embed assets
var assetsFS embed.FS

func webRoot() fs.FS {
	sub, _ := fs.Sub(webFS, "web")
	return sub
}

func assetBytes(name string) ([]byte, error) {
	return assetsFS.ReadFile("assets/" + name)
}

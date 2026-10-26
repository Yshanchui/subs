//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly

package main

import (
	"errors"
	"os"
)

func lockDataDir(string) (*os.File, error) {
	return nil, errors.New("服务端目前支持 Linux/macOS/BSD；其他系统请使用 Linux Docker 容器")
}

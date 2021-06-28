package GOBL

import (
	"fmt"
	"go/build"
)

// lisandro : try to use the uname -a to get the system infos

func main ()(){

	cont := build.Context{
		GOARCH: string("amd64"),
		GOOS: string("linux"),
		GOPATH: string(""),
		GOROOT: string(""),
	}

	fmt.Println(cont)

}
package main

import (
	"fmt"
	"os"
)

func is_dir(path string)(bool){
	name := path
	fi, err := os.Stat(name)
	if err != nil {
		fmt.Println(err)
		return false
	}
	switch mode := fi.Mode(); {
	case mode.IsDir():
		return true
	case mode.IsRegular():
		return false
	}
	return false
}

func main ()(){
	fmt.Println("hello world !")
	fmt.Scanf("hello : ")
}
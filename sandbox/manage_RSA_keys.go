package main

import (
	"fmt"
	"runtime"
	"time"
)

func init()(){
	fmt.Println(runtime.NumCPU())
}

func run(name string) {
	for i := 0; i < 3; i++ {
		time.Sleep(1 * time.Second) // attendre 1 seconde
		fmt.Println(name, " : ", i)
	}
}

func main() {
	debut := time.Now()         //debut := time.Now()
	go run("Hatim")       //run("Hatim")
	go run("Robert")      //run("Robert")
	run("Alex")           //run("Alex")
	fin := time.Now()           //fin := time.Now()
	fmt.Println(fin.Sub(debut)) //fmt.Println(fin.Sub(debut))

}
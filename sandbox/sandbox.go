package main

import (
	"fmt"
	"math/rand"
)

var hex = []uint8("0123456798abcdefgh")

func random_hex(n int) string {
	b := make([]uint8, n)
	for i := range b {
		b[i] = hex[rand.Intn(len(hex))]
	}
	return string(b)
}

func main()(){
	//fmt.Println(random_hex(30))
	i := 0
	for ; i<=69420; i++{
		ransom_ID := random_hex(30)
		set := make(map[string]struct{})
		set[ransom_ID] = struct{}{}
		// ...
		x := ransom_ID

		for key := range(set) {
			fmt.Println(key)
		}
		// each value will be printed only once, in no particular order

		set[x] = struct{}{}
		// you can use the ,ok idiom to check for existing keys
		if _, ok := set[ransom_ID]; ok {
			fmt.Println("element found")
		} else {
			fmt.Println("element not found")
		}
	}
}

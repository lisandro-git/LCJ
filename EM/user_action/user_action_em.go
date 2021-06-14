package main

import (
	"syscall"
	"time"
)

// edode : if a value returns "true", this means that the code is running in a sandbox

var (
	user32			 = syscall.NewLazyDLL("user32.dll")
	kernel32		 = syscall.NewLazyDLL("Kernel32.dll")
	getAsyncKeyState = user32.NewProc("GetAsyncKeyState")
)

func evade_clicks_count()(bool){
	/*
		source :
			- https://github.com/Arvanaghi/CheckPlease/blob/master/Go/click_tracker.go
		linked variables :
			- user32
			- getAsyncKeyState
		linked functions :
			-
	*/
	var count int
	var max_idle_time = 300
	t := time.Now()
	for count < 10  {
		left_click, _, _ := getAsyncKeyState.Call(uintptr(0x1))
		right_click, _, _ := getAsyncKeyState.Call(uintptr(0x2))
		if left_click % 2 == 1 {
			count += 1
			t = time.Now()
		}
		if right_click % 2 == 1 {
			count += 1
			t = time.Now()
		}
		if int(time.Since(t).Seconds()) > max_idle_time { return true }
	}
	return false;
}

func main() {

}
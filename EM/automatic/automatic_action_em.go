package main

import (
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// edode : if a value returns "true", this means that the code is running in a sandbox

var (
	user32			 = syscall.NewLazyDLL("user32.dll")
	getSystemMetrics = user32.NewProc("GetSystemMetrics")
)

func evade_screen_size()(bool) {
	/*
		source :
			- https://stackoverflow.com/a/48187712
		linked variable :
			- getSystemMetrics
		linked functions :
			-
	 */
	index_x := uintptr(0)
	index_y := uintptr(1)
	x, _, _ := getSystemMetrics.Call(index_x)
	y, _, _ := getSystemMetrics.Call(index_y)
	if x < 1024 || y < 768 {
		return true;
	}
	return false;
}

func get_window(funcName string) uintptr {
	proc := user32.NewProc(funcName)
	hwnd, _, _ := proc.Call()
	return hwnd
}
func evade_foreground_window()(bool){
	/*
		source :
			- https://gist.github.com/obonyojimmy/d6b263212a011ac7682ac738b7fb4c70
		linked variables :
			- user32
		linked functions :
			- get_window
	*/
	var temp uintptr
	for i := 0; i <= 5; i++ {
		if hwnd := get_window("GetForegroundWindow") ; hwnd != 0 {
			if hwnd != temp && temp != 0 { return true }
			temp = hwnd
		}
		time.Sleep(time.Second * 60)
	}
	return false;
}

var sandbox_mac_addresses = []string {
	"08:00:27", // VMWare
	"00:0C:29", // VMWare
	"00:1C:14", // VMWare
	"00:50:56", // VMWare
	"00:05:69", // VMWare
	"08:00:27", // VirtualBox
	"00:16:3E", // Xensources
	"00:1C:42", // Parallels
	"00:03:FF", // Microsoft
	"F0:1F:AF", // Dell
}
func get_mac_address() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	return as, nil
}
func evade_mac()(bool){
	/*
		source :
			- https://search.unprotect.it/technique/detecting-mac-address/
		linked variables :
			- sandbox_mac_addresses
		linked functions :
			- get_mac_address
	*/
	as, err := get_mac_address()
	if err != nil {
		log.Fatal(err)
	}
	var is_vm bool
	for _, s:= range sandbox_mac_addresses {
		for _, a := range as {
			str := strings.ToUpper(a)
			if str[0:8] == s[0:8] {
				is_vm = true
			}
		}
	}
	if is_vm { return true }
	return false
}

var sandbox_hostname = []string {
	"Sandbox",
	"Cuckoo",
	"Maltest",
	"Malware",
	"malsand",
	"ClonePC",
	"Fortinet",
	"Fortisandbox",
	"VIRUS",
}
func evade_hostname()(bool){
	/*
		source :
			- https://github.com/Arvanaghi/CheckPlease/blob/master/Go/hostname.go
		linked variables :
			- sandbox_hostname
		linked functions :
			-
	*/
	hostname, errorout := os.Hostname()
	if errorout != nil {
		os.Exit(1)
	}
	for _, host := range(sandbox_hostname){
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(host)) {
			return true;
		}
	}
	return false;
}

func main ()(){

}





















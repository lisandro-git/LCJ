package main

import (
	"io/ioutil"
	"log"
	"os"
)
import "reflect"
var black = []string{ // lisandro : evaluate symlink
	"bin",
	"boot",
	".cache",
	"dev",
	"etc",
	"initrd.img",
	"lib",
	"lib32",
	"lib64",
	"libx32",
	"lost+found",
	"media",
	"opt",
	"proc",
	"run",
	"sbin",
	"srv",
	"sys",
	"tmp",
	"usr",
	"var",
	"vmlinuz",
}

var white = []string{
	//"/root/y",
	"root",
	"home",
	"mnt",
}

func IOReadDir2(root string) ([]string) {
	var files []string
	fileInfo, err := ioutil.ReadDir(root)
	if err != nil {
		return files
	}
	for _, file := range fileInfo {
		files = append(files, file.Name())
	}
	return files
}

func in_array(val interface{}, array interface{}) (bool) {
	exists := false
	//index  := -1

	switch reflect.TypeOf(array).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(array)

		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(val, s.Index(i).Interface()) == true {
				//index = i
				exists = true
				return exists
			}
		}
	}
	return exists
}

func is_symlink(file string)(bool) {
	file = "/" + file
	fi, err := os.Lstat(file)
	if err != nil{
		log.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		return true
	} else {
		return false
	}
}
var x []string
func main() {
	root_files := IOReadDir2("/")
	for _, root := range(root_files){

		a := in_array(root, black)
		if a{
			//fmt.Println(root, "\t\texist ", b)
		} else {
			x = append(x, root)
		}
	}
	for _, dir :=range(x){
		if !is_symlink(dir){

		}
	}

}















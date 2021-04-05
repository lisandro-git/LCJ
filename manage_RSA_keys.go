package LCJ

//edode : according to https://stackoverflow.com/questions/13555085/save-and-load-crypto-rsa-privatekey-to-and-from-the-disk

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
	"os"
)

var key []byte

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
	new_key := []byte(rand_str(32))
	encrypted_new_key :=  encrypt_encryption_key(new_key)
	err := ioutil.WriteFile("/root/go/src/sandbox/key", encrypted_new_key, 0644)
	if err != nil {
		fmt.Printf("Error creating Key file!")
		os.Exit(0)
	}
	return new_key
}

func check_key() {
	the_key, err := ioutil.ReadFile("/root/go/src/sandbox/key") //Check to see if a key was already created
	if err != nil {
		key = createPrivKey() //If not, create one
	} else {
		key = the_key //If so, set key as the key found in the file
	}
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
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

func import_public_key() rsa.PublicKey {
	// Create the keys
	//priv, pub := GenerateRsaKeyPair()

	// Export the keys to pem string
	//priv_pem   := ExportRsaPrivateKeyAsPemStr(priv)
	//pub_pem, _ := ExportRsaPublicKeyAsPemStr(pub)

	pub_pem  := `-----BEGIN RSA PUBLIC KEY-----
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

	// Import the keys from pem stringhe *rsa.PrivateKey struct comes
	//priv_parsed, _ := ParseRsaPrivateKeyFromPemStr(priv_pem)
	pub_parsed, _ := ParseRsaPublicKeyFromPemStr(pub_pem)

	// Export the newly imported keys
	//priv_parsed_pem := ExportRsaPrivateKeyAsPemStr(priv_parsed)
	//pub_parsed_pem , _ := ExportRsaPublicKeyAsPemStr(pub_parsed)
	//return priv_pem, &priv_parsed
	return *pub_parsed
}

func import_private_key() *rsa.PrivateKey{
	// Create the keys
	//priv, pub := GenerateRsaKeyPair()

	// Export the keys to pem string
	priv_pem := `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

	// Import the keys from pem string
	priv_parsed, _ := ParseRsaPrivateKeyFromPemStr(priv_pem)

	// Export the newly imported keys
	//priv_parsed_pem := ExportRsaPrivateKeyAsPemStr(priv_parsed)

	return priv_parsed
}

func encrypt_encryption_key(k []byte) []byte {
	public_key  := import_public_key()
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&public_key,
		[]byte(k),
		nil)
	if err != nil {
		panic(err)
	}
	//fmt.Println("encrypted bytes: ", encryptedBytes)
	return encryptedBytes
}

func main() {

	check_key()
/*	edode : decrypt the key file

	// edode : uint8 is like byte
	content, err := ioutil.ReadFile("/root/go/src/sandbox/key")

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(content))

    private_key := import_private_key()
	decryptedBytes, err := private_key.Decrypt(
		nil,
		content,
		&rsa.OAEPOptions{Hash: crypto.SHA256})

	if err != nil {
		panic(err)
	}
	fmt.Println("decrypted message: ", string(decryptedBytes)) //edode : display the decrypted key file

*/

}






























package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

// genAddress sinh ra một địa chỉ Bitcoin ngẫu nhiên (Base58Check)
func genAddress() (string, *ecdsa.PrivateKey, error) {
	// 1. Sinh cặp khóa ECDSA
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	pubKey := append(privKey.PublicKey.X.Bytes(), privKey.PublicKey.Y.Bytes()...)

	// 2. SHA256 rồi RIPEMD160
	shaHash := sha256.Sum256(pubKey)
	ripemd := ripemd160.New()
	_, err = ripemd.Write(shaHash[:])
	if err != nil {
		return "", nil, err
	}
	pubKeyHash := ripemd.Sum(nil)

	// 3. Thêm version byte (0x00)
	versionedPayload := append([]byte{0x00}, pubKeyHash...)

	// 4. Checksum (SHA256 2 lần, lấy 4 byte đầu)
	firstSHA := sha256.Sum256(versionedPayload)
	secondSHA := sha256.Sum256(firstSHA[:])
	checksum := secondSHA[:4]

	// 5. Nối lại
	fullPayload := append(versionedPayload, checksum...)

	// 6. Encode Base58
	address := base58.Encode(fullPayload)

	return address, privKey, nil
}

// func main() {
// 	address, privKey, err := genAddress()
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}
// 	fmt.Println("Address:", address)
// 	fmt.Printf("Private key: %x\n", privKey.D.Bytes())
// }

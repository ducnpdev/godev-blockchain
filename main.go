package main

import "fmt"

func main() {
	address, privKey, err := genAddress()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Address:", address)
	fmt.Printf("Private key: %x\n", privKey.D.Bytes())
}

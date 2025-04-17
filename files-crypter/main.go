package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"os"
)

func main() {
	// Generate a random key
	key, err := generateKey(32) // AES-256 key size
	// Error handling
	if err != nil {
		panic(errors.New("Error generating key: " + err.Error()))
	}

	// Save key to file
	keyFile, err := os.Create("key.txt")
	if err != nil {
		panic(errors.New("Error creating key file: " + err.Error()))
	}
	defer keyFile.Close()

	_, err = keyFile.Write(key)
	if err != nil {
		panic(errors.New("Error writing key to file: " + err.Error()))
	}
	// Encrypt a file
	err = encryptFile(key, "example.txt", "example.txt.aes")
	if err != nil {
		panic(errors.New("Error encrypting file: " + err.Error()))
	}

	// Decrypt the file
	err = decryptFile(key, "example.txt.aes", "example_decrypted.txt")
	if err != nil {
		panic(err)
	}
}

func generateKey(length int) ([]byte, error) {
	// Create byte array of the specified length
	key := make([]byte, length)
	// Read random bytes into the key
	_, err := rand.Read(key)
	// Error handling
	if err != nil {
		return nil, err
	}
	// Return the generated key
	return key, nil
}

func encryptFile(key []byte, inputPath, outputPath string) error {

	// Open the input file for reading
	inFile, err := os.Open(inputPath)
	// Error handling
	if err != nil {
		return err
	}
	// Ensure the input file is closed after processing
	defer inFile.Close()

	// Create the new output file
	outFile, err := os.Create(outputPath)
	// Error handling
	if err != nil {
		return err
	}

	// Ensure the output file is closed after processing
	defer outFile.Close()

	// Read the input file in chunks
	blocks, err := aes.NewCipher(key)
	// Error handling
	if err != nil {
		return err
	}

	// Create a buffer to hold the data
	aesGCM, err := cipher.NewGCM(blocks)
	// Error handling
	if err != nil {
		return err
	}
	// Create a nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	// Write nonce to the output file
	if _, err := outFile.Write(nonce); err != nil {
		return err
	}

	plainText, err := io.ReadAll(inFile)
	// Error handling
	if err != nil {
		return err
	}
	// Encrypt the data
	cipherText := aesGCM.Seal(nil, nonce, plainText, nil)
	_, err = outFile.Write(cipherText)
	if err != nil {
		return err
	}

	log.Println("File encrypted successfully: ", outputPath)

	return err
}

func decryptFile(key []byte, inputPath, outputPath string) error {
	// open input file
	inFile, err := os.Open(inputPath)
	// Error handling
	if err != nil {
		return err
	}
	defer inFile.Close()

	// Create blocks
	block, err := aes.NewCipher(key)
	// Error handling
	if err != nil {
		return err
	}
	// Create GCM
	aesGCM, err := cipher.NewGCM(block)
	// Error handling
	if err != nil {
		return err
	}

	// Create nonce byte array
	nonce := make([]byte, aesGCM.NonceSize())

	// Read nonce from the beginning of the file
	if _, err := io.ReadFull(inFile, nonce); err != nil {
		return err
	}
	// read the rest of the file
	ciphertext, err := io.ReadAll(inFile)
	// Error handling
	if err != nil {
		return err
	}
	// Decrypt data

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	// Error handling
	if err != nil {
		return err
	}
	// write decrypted data to output file
	outFile, err := os.Create(outputPath)
	// Error handling
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Write decrypted data to the output file
	_, err = outFile.Write(plaintext)
	log.Println("File decrypted successfully: ", outputPath)
	return err
}

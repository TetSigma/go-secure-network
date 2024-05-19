package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// Node represents a node in the network
type Node struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	next       *Node
}

type User struct {
	nodes []*Node
}

func NewUser(nodeCount int) *User {
	user := &User{}
	for i := 0; i < nodeCount; i++ {
		user.nodes = append(user.nodes, NewNode())
	}
	return user
}

// NewNode creates a new node with RSA key pair
func NewNode() *Node {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &Node{
		publicKey:  &privateKey.PublicKey,
		privateKey: privateKey,
	}
}

// EncryptSymmetric encrypts a message using symmetric key (AES)
func EncryptSymmetric(message []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], message)
	return ciphertext, nil
}

// DecryptSymmetric decrypts a message using symmetric key (AES)
func DecryptSymmetric(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// EncryptRSA encrypts a message using RSA
func EncryptRSA(message []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
}

// DecryptRSA decrypts a message using RSA
func DecryptRSA(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
}

// Mix mixes messages received from different nodes
func Mix(senderNodes []*Node, recipientNodes []*Node, message []byte) ([]byte, error) {
	// Generate a random symmetric key
	symmetricKey := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, symmetricKey); err != nil {
		return nil, err
	}

	// Encrypt the message using the symmetric key (AES)
	encryptedMessage, err := EncryptSymmetric(message, symmetricKey)
	if err != nil {
		return nil, err
	}

	// Encrypt the symmetric key with each recipient node's public key
	for _, node := range recipientNodes {
		encryptedKey, err := EncryptRSA(symmetricKey, node.publicKey)
		if err != nil {
			return nil, err
		}
		// Append the encrypted symmetric key to the encrypted message
		encryptedMessage = append(encryptedMessage, encryptedKey...)
	}

	return encryptedMessage, nil
}

// Demix decrypts a mixed message
func Demix(senderNodes []*Node, recipientNodes []*Node, ciphertext []byte) ([]byte, error) {
	// The last part of the ciphertext is the actual encrypted message
	encryptedMessage := ciphertext[:len(ciphertext)-len(recipientNodes)*256]

	// The rest are the encrypted symmetric keys
	encryptedKeys := ciphertext[len(ciphertext)-len(recipientNodes)*256:]

	// Decrypt the symmetric keys with the recipient nodes' private keys
	symmetricKeys := make([][]byte, len(recipientNodes))
	for i, node := range recipientNodes {
		encryptedKey := encryptedKeys[i*256 : (i+1)*256]
		symmetricKey, err := DecryptRSA(encryptedKey, node.privateKey)
		if err != nil {
			return nil, err
		}
		symmetricKeys[i] = symmetricKey
	}

	// Find the index of the sender node
	var senderIndex int
	for i, senderNode := range senderNodes {
		for _, recipientNode := range recipientNodes {
			if senderNode == recipientNode {
				senderIndex = i
				break
			}
		}
	}

	// Decrypt the message using the sender node's recovered symmetric key
	decryptedMessage, err := DecryptSymmetric(encryptedMessage, symmetricKeys[senderIndex])
	if err != nil {
		return nil, err
	}

	return decryptedMessage, nil
}

func main() {
	// Create users A and B
	userA := NewUser(3)
	userB := NewUser(3)

	reader := bufio.NewReader(os.Stdin)
	for {
		// Prompt user A to enter a message
		fmt.Print("User A, enter a message to send to User B (or type 'quit' to exit): ")
		messageA, _ := reader.ReadString('\n')

		// Check if user A wants to quit
		if messageA == "quit\n" {
			break
		}

		// Prompt user B to enter a message
		fmt.Print("User B, enter a message to send to User A (or type 'quit' to exit): ")
		messageB, _ := reader.ReadString('\n')

		// Check if user B wants to quit
		if messageB == "quit\n" {
			break
		}

		// Convert messages to []byte
		messageBytesA := []byte(messageA)
		messageBytesB := []byte(messageB)

		// Mix and send messages
		mixedMessageAtoB, err := Mix(userA.nodes, userB.nodes, messageBytesA)
		if err != nil {
			fmt.Println("Error mixing message from User A to User B:", err)
			return
		}

		mixedMessageBtoA, err := Mix(userB.nodes, userA.nodes, messageBytesB)
		if err != nil {
			fmt.Println("Error mixing message from User B to User A:", err)
			return
		}

		// Print encrypted messages
		fmt.Println("Encrypted Message from User A to User B:", string(mixedMessageAtoB))
		fmt.Println("Encrypted Message from User B to User A:", string(mixedMessageBtoA))

		// Simulate message exchange (in a real scenario, these would be sent over the network)
		demixedMessageAtoB, err := Demix(userA.nodes, userB.nodes, mixedMessageAtoB)
		if err != nil {
			fmt.Println("Error demixing message from User A to User B:", err)
			return
		}

		demixedMessageBtoA, err := Demix(userB.nodes, userA.nodes, mixedMessageBtoA)
		if err != nil {
			fmt.Println("Error demixing message from User B to User A:", err)
			return
		}

		// Print decrypted messages
		fmt.Println("Decrypted Message from User A to User B:", string(demixedMessageAtoB))
		fmt.Println("Decrypted Message from User B to User A:", string(demixedMessageBtoA))
	}
}

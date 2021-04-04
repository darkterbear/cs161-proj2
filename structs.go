package proj2

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/cs161-staff/userlib"
)

type SymKeyset struct {
	EKey []byte // Encryption key
	MKey []byte // MAC key
}

func (sks SymKeyset) Encrypt(plaintext []byte) []byte {
	// Generate random IV
	iv := userlib.RandomBytes(16)

	// Symmetric encrypt
	ciphertext := userlib.SymEnc(sks.EKey, iv, plaintext)

	// MAC (64 bytes)
	mac, err := userlib.HMACEval(sks.MKey, ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	result, err := json.Marshal(map[string][]byte{
		"mac":        mac,
		"ciphertext": ciphertext,
	})

	if err != nil {
		log.Fatal(err)
	}

	return result
}

func (sks SymKeyset) Decrypt(r []byte) ([]byte, error) {
	var result map[string][]byte
	json.Unmarshal(r, &result)

	mac, ciphertext := result["mac"], result["ciphertext"]
	compMac, err := userlib.HMACEval(sks.MKey, ciphertext)

	if err != nil {
		log.Fatal(err)
	}

	if !userlib.HMACEqual(compMac, mac) {
		// HMAC does not match the given ciphertext
		return nil, errors.New("HMAC corrupted in SymKey decrypt")
	}

	return userlib.SymDec(sks.EKey, ciphertext), nil
}

type PubKeyset struct {
	EKey userlib.PublicKeyType // PKE encryption key
	VKey userlib.PublicKeyType // PKS verification key
}

func Encrypt(EKey userlib.PKEEncKey, SKey userlib.DSSignKey, plaintext []byte) []byte {
	ciphertext, err := userlib.PKEEnc(EKey, plaintext)

	if err != nil {
		log.Fatal(err)
	}

	signature, err := userlib.DSSign(SKey, ciphertext)

	if err != nil {
		log.Fatal(err)
	}

	result, err := json.Marshal(map[string][]byte{
		"signature":  signature,
		"ciphertext": ciphertext,
	})

	if err != nil {
		log.Fatal(err)
	}

	return result
}

func Decrypt(DKey userlib.PKEDecKey, VKey userlib.DSVerifyKey, r []byte) ([]byte, error) {
	var result map[string][]byte
	json.Unmarshal(r, &result)

	signature, ciphertext := result["signature"], result["ciphertext"]

	if userlib.DSVerify(VKey, ciphertext, signature) != nil {
		return nil, errors.New("digital signature not valid for decryption")
	}

	plaintext, err := userlib.PKEDec(DKey, ciphertext)

	if err != nil {
		log.Fatal(err)
	}

	return plaintext, nil
}

type PrivKeyset struct {
	DKey userlib.PrivateKeyType // PKE decryption key
	SKey userlib.PrivateKeyType // PKS signing key
}

type User struct {
	Username     string
	SymKeys      SymKeyset
	PrivKeys     PrivKeyset
	FileNameSalt []byte
}

type FileMeta struct {
	Owner       string
	FilePointer []byte
	NodePointer []byte
}

func (fm FileMeta) RevocationCheck(u User) bool {
	// TODO: Implement
	return false
}

type FileNode struct {
	Username      string
	IsRoot        bool
	ChildPointers []Pointer
}

func (fn FileNode) GetChildren() []FileNode {
	// TODO: Implement
	return []FileNode{}
}

type Pointer struct {
	ID   []byte
	Keys SymKeyset
}

package proj2

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
)

type AuthenticatedConfidentialMsg struct {
	Authentication []byte
	Ciphertext     []byte
}

type SymKeyset struct {
	EKey []byte // Encryption key
	MKey []byte // MAC key
}

func pad(plaintext []byte) []byte {
	blockSize := userlib.AESBlockSizeBytes
	remainder := blockSize - len(plaintext)%blockSize
	remainderFill := make([]byte, remainder)

	adjustedPlaintext := append(plaintext, remainderFill...)

	lastBlock := make([]byte, blockSize)
	lastBlock[0] = byte(remainder)

	adjustedPlaintext = append(adjustedPlaintext, lastBlock...)
	return adjustedPlaintext
}

func depad(paddedPlaintext []byte) []byte {
	blockSize := userlib.AESBlockSizeBytes
	lastBlock := paddedPlaintext[len(paddedPlaintext)-blockSize:]
	padSize := lastBlock[0]

	return paddedPlaintext[:len(paddedPlaintext)-blockSize-int(padSize)]
}

func (sks SymKeyset) Encrypt(plaintext []byte) []byte {
	// Pad
	plaintext = pad(plaintext)

	// Generate random IV
	iv := userlib.RandomBytes(16)

	// Symmetric encrypt
	ciphertext := userlib.SymEnc(sks.EKey, iv, plaintext)

	// MAC (64 bytes)
	mac, err := userlib.HMACEval(sks.MKey, ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	result, err := json.Marshal(AuthenticatedConfidentialMsg{
		Authentication: mac,
		Ciphertext:     ciphertext,
	})

	if err != nil {
		log.Fatal(err)
	}

	return result
}

func (sks SymKeyset) Decrypt(r []byte) ([]byte, error) {
	var result AuthenticatedConfidentialMsg
	json.Unmarshal(r, &result)

	mac, ciphertext := result.Authentication, result.Ciphertext
	compMac, err := userlib.HMACEval(sks.MKey, ciphertext)

	if err != nil {
		log.Fatal(err)
	}

	if !userlib.HMACEqual(compMac, mac) {
		// HMAC does not match the given ciphertext
		return nil, errors.New("HMAC corrupted in SymKey decrypt")
	}

	return depad(userlib.SymDec(sks.EKey, ciphertext)), nil
}

type PubKeyset struct {
	EKey userlib.PublicKeyType // PKE encryption key
	VKey userlib.PublicKeyType // PKS verification key
}

func PubEncrypt(EKey userlib.PKEEncKey, SKey userlib.DSSignKey, plaintext []byte) []byte {
	ciphertext, err := userlib.PKEEnc(EKey, plaintext)

	if err != nil {
		log.Fatal(err)
	}

	signature, err := userlib.DSSign(SKey, ciphertext)

	if err != nil {
		log.Fatal(err)
	}

	result, err := json.Marshal(AuthenticatedConfidentialMsg{
		Authentication: signature,
		Ciphertext:     ciphertext,
	})

	if err != nil {
		log.Fatal(err)
	}

	return result
}

func PubDecrypt(DKey userlib.PKEDecKey, VKey userlib.DSVerifyKey, r []byte) ([]byte, error) {
	var result AuthenticatedConfidentialMsg
	json.Unmarshal(r, &result)

	signature, ciphertext := result.Authentication, result.Ciphertext

	// check signature associated with each piece of ciphertext
	if userlib.DSVerify(VKey, ciphertext, signature) != nil {
		return nil, errors.New("digital signature not valid for decryption")
	}

	plaintext, err := userlib.PKEDec(DKey, ciphertext)

	// check if decryption worked properly
	if err != nil {
		return nil, errors.New("error attempting to decrypt ciphertext with PKE decryption key")
	}

	return plaintext, nil
}

type PrivKeyset struct {
	DKey userlib.PrivateKeyType // PKE decryption key
	SKey userlib.PrivateKeyType // PKS signing key
}

type User struct {
	Username string
	SymKeys  SymKeyset
	PrivKeys PrivKeyset
	UserSalt []byte
}

type PrivKeyLocationParams struct {
	Username string
	UserSalt []byte
}

type FileMeta struct {
	Owner       string
	Filename    string
	FilePointer Pointer
	NodePointer Pointer
}

type RevocationNoticeLocationParams struct {
	FileID   userlib.UUID
	Username string
}

type UserFileDirectoryParams struct {
	Username string
	Filename string
	UserSalt []byte
}

/*
	The revocation check serves 2 purposes:
	1. If the file has moved to another location and reencrypted due to someone else being revoked, update our file metadata with the new secure pointer.
	2. Return whether or not we still have access to the file
*/
func (fm FileMeta) RevocationCheck(u User) (bool, error) {
	paramsMarshalled, err := json.Marshal(RevocationNoticeLocationParams{
		FileID:   fm.FilePointer.ID,
		Username: u.Username,
	})

	if err != nil {
		log.Fatal(err)
	}

	revocationNoticeLocation, err := uuid.FromBytes(userlib.Hash(paramsMarshalled)[:16])

	if err != nil {
		log.Fatal(err)
	}

	value, ok := userlib.DatastoreGet(revocationNoticeLocation)

	if ok {
		// There exists a revocation notice

		// Get owner DS verification key
		VKey, ok := userlib.KeystoreGet(fm.Owner + "_v")
		if !ok {
			return false, errors.New("cannot get verification key for file owner to verify revocation notice")
		}

		// Decrypt and verify revocation notice
		plaintext, err := PubDecrypt(u.PrivKeys.DKey, VKey, value)

		if err != nil {
			return false, errors.New("failed to decrypt revocation notice")
		}

		var newFilePointer Pointer
		json.Unmarshal(plaintext, &newFilePointer)

		// Update this FileMeta's FilePointer
		fm.FilePointer = newFilePointer

		// Update stored directory entry
		fmMarshalled, err := json.Marshal(fm)
		if err != nil {
			log.Fatal(err)
		}

		ciphertext := u.SymKeys.Encrypt(fmMarshalled)

		userDirectoryParamsMarshalled, err := json.Marshal(UserFileDirectoryParams{
			Username: u.Username,
			Filename: fm.Filename,
			UserSalt: u.UserSalt,
		})

		if err != nil {
			log.Fatal(err)
		}

		userDirectoryUUID, err := uuid.FromBytes(userlib.Hash(userDirectoryParamsMarshalled)[:16])
		if err != nil {
			log.Fatal(err)
		}

		userlib.DatastoreSet(userDirectoryUUID, ciphertext)
	}

	// Check that we still have access
	fileIDMarshalled, err := json.Marshal(fm.FilePointer.ID)
	if err != nil {
		log.Fatal(err)
	}

	fileDataUUID, err := uuid.FromBytes(userlib.Hash(fileIDMarshalled)[:16])
	if err != nil {
		log.Fatal(err)
	}

	_, ok = userlib.DatastoreGet(fileDataUUID)
	return ok, nil
}

type FileNode struct {
	Username      string
	IsRoot        bool
	ChildPointers []Pointer
}

func (fn FileNode) GetChildren() ([]FileNode, error) {
	children := []FileNode{}
	for _, childPointer := range fn.ChildPointers {
		encryptedFileNode, ok := userlib.DatastoreGet(childPointer.ID)
		if !ok {
			return nil, errors.New("failed to retrieve file node from pointer")
		}
		fileNode, err := childPointer.Keys.Decrypt(encryptedFileNode)
		if err != nil {
			return nil, errors.New("failed to decrypt file node")
		}
		var result FileNode
		json.Unmarshal(fileNode, &result)
		children = append(children, result)
	}
	return children, nil
}

type Pointer struct {
	ID   userlib.UUID
	Keys SymKeyset
}

type FileChunkLocationParams struct {
	FileID userlib.UUID
	Chunk  int
}

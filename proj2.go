package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func bytesEqual(a, b []byte) bool {
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// Verify if user exists in the keystore
func userExists(username string) bool {
	_, vOk := userlib.KeystoreGet(username + "_v")
	_, eOk := userlib.KeystoreGet(username + "_e")
	return vOk || eOk
}

func deriveKeys(username string, password string) (SymKeyset, []byte) {
	masterKey := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)
	eKey, _ := userlib.HashKDF(masterKey, []byte("encryption"))
	mKey, _ := userlib.HashKDF(masterKey, []byte("mac"))
	userSalt, _ := userlib.HashKDF(masterKey, []byte("userSalt"))

	return SymKeyset{
		EKey: eKey,
		MKey: mKey,
	}, userSalt
}

// Verifies that values encrypted by a stored public key can be decrypted by the given private key
func verifyKeypairs(pubks PubKeyset, privks PrivKeyset) bool {
	bytes := userlib.RandomBytes(256)
	encrypted := PubEncrypt(pubks.EKey, privks.SKey, bytes)
	dbytes, err := PubDecrypt(privks.DKey, pubks.VKey, encrypted)
	if err != nil {
		return false
	}

	return bytesEqual(bytes, dbytes)
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	if userExists(username) {
		return nil, errors.New("username already exists")
	}

	symKeys, userSalt := deriveKeys(username, password)
	ePubKey, ePrivKey, _ := userlib.PKEKeyGen()
	sPrivKey, sPubKey, _ := userlib.DSKeyGen()

	privKeyset := PrivKeyset{
		DKey: ePrivKey,
		SKey: sPrivKey,
	}

	privKeysetMarshalled, _ := json.Marshal(privKeyset)

	ciphertext := symKeys.Encrypt(privKeysetMarshalled)

	privKeyLocationMarshalled, _ := json.Marshal(PrivKeyLocationParams{
		Username: username,
		UserSalt: userSalt,
	})

	privKeyUUID, _ := uuid.FromBytes(userlib.Hash(privKeyLocationMarshalled))
	userlib.DatastoreSet(privKeyUUID, ciphertext)

	userlib.KeystoreSet(username+"_e", ePubKey)
	userlib.KeystoreSet(username+"_v", sPubKey)

	return &User{
		Username: username,
		SymKeys:  symKeys,
		PrivKeys: privKeyset,
		UserSalt: userSalt,
	}, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	// Check that user exists
	if !userExists(username) {
		return nil, errors.New("invalid credentials")
	}

	// Derive symmetric keys
	symKeys, userSalt := deriveKeys(username, password)

	// Fetch and decrypt private keys
	privKeyLocationMarshalled, _ := json.Marshal(PrivKeyLocationParams{
		Username: username,
		UserSalt: userSalt,
	})

	privksUUID, _ := uuid.FromBytes(userlib.Hash(privKeyLocationMarshalled))
	value, ok := userlib.DatastoreGet(privksUUID)

	if !ok {
		return nil, errors.New("invalid credentials")
	}

	plaintext, err := symKeys.Decrypt(value)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	var privks PrivKeyset
	json.Unmarshal(plaintext, &privks)

	// Fetch public keys
	var pubks PubKeyset
	pubks.EKey, ok = userlib.KeystoreGet(username + "_e")
	if !ok {
		return nil, errors.New("invalid credentials")
	}
	pubks.VKey, ok = userlib.KeystoreGet(username + "_v")
	if !ok {
		return nil, errors.New("invalid credentials")
	}

	// Verify keys are correct
	if !verifyKeypairs(pubks, privks) {
		return nil, errors.New("invalid credentials")
	}

	// Build and return user struct
	return &User{
		Username: username,
		SymKeys:  symKeys,
		PrivKeys: privks,
		UserSalt: userSalt,
	}, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	jsonData, _ := json.Marshal(data)
	userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	return dataBytes, nil
	//End of toy implementation

	return
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	return
}

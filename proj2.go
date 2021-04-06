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

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

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
		EKey: eKey[:16],
		MKey: mKey[:16],
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

	privKeyUUID, _ := uuid.FromBytes(userlib.Hash(privKeyLocationMarshalled)[:16])
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

	privksUUID, _ := uuid.FromBytes(userlib.Hash(privKeyLocationMarshalled)[:16])
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
func (u *User) StoreFile(filename string, data []byte) (err error) {
	// Generate UUIDs and file keys
	fileID := uuid.New()
	nodeID := uuid.New()

	fileSymKeyset := SymKeyset{
		EKey: userlib.RandomBytes(16),
		MKey: userlib.RandomBytes(16),
	}

	nodeSymKeyset := SymKeyset{
		EKey: userlib.RandomBytes(16),
		MKey: userlib.RandomBytes(16),
	}

	// Encrypt and save data
	numChunksMarshalled, _ := json.Marshal(1)
	numChunksEncrypted := fileSymKeyset.Encrypt(numChunksMarshalled)
	fileIDMarshalled, _ := json.Marshal(fileID)
	fileChunksUUID, _ := uuid.FromBytes(userlib.Hash(fileIDMarshalled)[:16])

	dataEncrypted := fileSymKeyset.Encrypt(data)
	dataLocationMarshalled, _ := json.Marshal(FileChunkLocationParams{
		FileID: fileID,
		Chunk:  0,
	})
	dataLocationUUID, _ := uuid.FromBytes(userlib.Hash(dataLocationMarshalled)[:16])

	userlib.DatastoreSet(fileChunksUUID, numChunksEncrypted)
	userlib.DatastoreSet(dataLocationUUID, dataEncrypted)

	filePointer := Pointer{
		ID:   fileID,
		Keys: fileSymKeyset,
	}

	// Create file share hierarchy (root node)
	fileNodeMarshalled, _ := json.Marshal(FileNode{
		Username:      u.Username,
		IsRoot:        true,
		ChildPointers: []Pointer{},
	})
	fileNodeEncrypted := nodeSymKeyset.Encrypt(fileNodeMarshalled)
	userlib.DatastoreSet(nodeID, fileNodeEncrypted)

	nodePointer := Pointer{
		ID:   nodeID,
		Keys: nodeSymKeyset,
	}

	// Create file directory entry for this user
	fileMetaMarshalled, _ := json.Marshal(FileMeta{
		Owner:       u.Username,
		Filename:    filename,
		FilePointer: filePointer,
		NodePointer: nodePointer,
	})
	fileMetaEncrypted := u.SymKeys.Encrypt(fileMetaMarshalled)

	fileDirectoryMarshalled, _ := json.Marshal(UserFileDirectoryParams{
		Username: u.Username,
		Filename: filename,
		UserSalt: u.UserSalt,
	})
	fileDirectoryUUID, _ := uuid.FromBytes(userlib.Hash(fileDirectoryMarshalled)[:16])

	userlib.DatastoreSet(fileDirectoryUUID, fileMetaEncrypted)

	return nil
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (u *User) AppendFile(filename string, data []byte) (err error) {
	fileDirectoryMarshalled, _ := json.Marshal(UserFileDirectoryParams{
		Username: u.Username,
		Filename: filename,
		UserSalt: u.UserSalt,
	})
	fileDirectoryUUID, _ := uuid.FromBytes(userlib.Hash(fileDirectoryMarshalled)[:16])
	fileMetaEncrypted, ok := userlib.DatastoreGet(fileDirectoryUUID)

	if !ok {
		return errors.New("file not found")
	}

	fileMetaBytes, err := u.SymKeys.Decrypt(fileMetaEncrypted)

	if err != nil {
		return err
	}

	var fileMeta FileMeta
	json.Unmarshal(fileMetaBytes, &fileMeta)

	access, err := fileMeta.RevocationCheck(*u)
	if !access {
		return errors.New("you no longer have access to this file")
	}

	if err != nil {
		return errors.New("cannot verify/decrypt revocation notice")
	}

	filePointer := fileMeta.FilePointer

	// Get number of chunks
	fileIDMarshalled, _ := json.Marshal(filePointer.ID)
	fileChunksUUID, _ := uuid.FromBytes(userlib.Hash(fileIDMarshalled)[:16])
	numChunksEncrypted, ok := userlib.DatastoreGet(fileChunksUUID)

	if !ok {
		return errors.New("failed to retrieve num chunks")
	}

	fileChunksBytes, err := filePointer.Keys.Decrypt(numChunksEncrypted)

	if err != nil {
		return err
	}

	var numChunks int
	json.Unmarshal(fileChunksBytes, &numChunks)

	numChunks++

	// Save new chunk count
	numChunksMarshalled, _ := json.Marshal(numChunks)
	numChunksEncrypted = filePointer.Keys.Encrypt(numChunksMarshalled)
	userlib.DatastoreSet(fileChunksUUID, numChunksEncrypted)

	// Save new chunk
	dataEncrypted := filePointer.Keys.Encrypt(data)
	dataLocationMarshalled, _ := json.Marshal(FileChunkLocationParams{
		FileID: filePointer.ID,
		Chunk:  numChunks - 1,
	})
	dataLocationUUID, _ := uuid.FromBytes(userlib.Hash(dataLocationMarshalled)[:16])

	userlib.DatastoreSet(dataLocationUUID, dataEncrypted)

	return nil
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (u *User) LoadFile(filename string) (dataBytes []byte, err error) {
	userFileDirectoryParamsMarshaled, _ := json.Marshal(UserFileDirectoryParams{
		Username: u.Username,
		Filename: filename,
		UserSalt: u.UserSalt,
	})

	userFileDirectoryParamsUUID, _ := uuid.FromBytes(userlib.Hash(userFileDirectoryParamsMarshaled)[:16])

	// grab encrypted file metadata from the datastore
	ciphertext, ok := userlib.DatastoreGet(userFileDirectoryParamsUUID)

	if !ok {
		return nil, errors.New("failed to retrive file metadata")
	}

	plaintext, err := u.SymKeys.Decrypt(ciphertext)

	if err != nil {
		return nil, errors.New("failed to decrypt file metadata")
	}

	var fileMeta FileMeta
	json.Unmarshal(plaintext, &fileMeta)

	// check for file data access
	access, err := fileMeta.RevocationCheck(*u)
	if !access {
		return nil, errors.New("you no longer have access to this file")
	}

	if err != nil {
		return nil, errors.New("cannot verify/decrypt revocation notice")
	}

	filePointer := fileMeta.FilePointer
	fileIDMarshalled, _ := json.Marshal(filePointer.ID)
	fileChunksUUID, _ := uuid.FromBytes(userlib.Hash(fileIDMarshalled)[:16])

	// retrieve the number of file chunks from the datastore
	numChunksEncrypted, ok := userlib.DatastoreGet(fileChunksUUID)

	if !ok {
		return nil, errors.New("failed to retrieve num chunks")
	}

	fileChunksBytes, err := filePointer.Keys.Decrypt(numChunksEncrypted)

	if err != nil {
		return nil, err
	}

	var numChunks int
	json.Unmarshal(fileChunksBytes, &numChunks)

	fileData := []byte{}

	for i := 0; i < numChunks; i++ {
		dataLocationMarshalled, _ := json.Marshal(FileChunkLocationParams{
			FileID: filePointer.ID,
			Chunk:  i,
		})
		dataLocationUUID, _ := uuid.FromBytes(userlib.Hash(dataLocationMarshalled)[:16])

		// retrieve the encrypted file chunk data from the datastore
		ciphertext, ok := userlib.DatastoreGet(dataLocationUUID)

		if !ok {
			return nil, errors.New("failed to retrieve file chunk")
		}

		fileDataChunk, err := filePointer.Keys.Decrypt(ciphertext)

		if err != nil {
			return nil, err
		}

		// concat the file chunks
		fileData = append(fileData, fileDataChunk...)
	}

	return fileData, nil
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

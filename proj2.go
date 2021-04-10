package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"log"

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

type AccessTokenInfo struct {
	SymKeyCipher   []byte
	FileMetaCipher []byte
}

/*
	The revocation check serves 2 purposes:
	1. If the file has moved to another location and reencrypted due to someone else being revoked, update our file metadata with the new secure pointer.
	2. Return whether or not we still have access to the file
*/
func (fm *FileMeta) RevocationCheck(u User) (bool, error) {
	revocationNoticeLocation := toUUID(RevocationNoticeLocationParams{
		FileID:   fm.FilePointer.ID,
		Username: u.Username,
	})

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
		ciphertext := encryptStruct(fm, u.SymKeys)

		userDirectoryUUID := toUUID(UserFileDirectoryParams{
			Username: u.Username,
			Filename: fm.Filename,
			UserSalt: u.UserSalt,
		})

		userlib.DatastoreSet(userDirectoryUUID, ciphertext)
	}

	// Check that we still have access
	fileDataUUID := toUUID(fm.FilePointer.ID)
	_, ok = userlib.DatastoreGet(fileDataUUID)
	return ok, nil
}

type FileNode struct {
	Username      string
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

func toUUID(obj interface{}) uuid.UUID {
	marshalled, err := json.Marshal(obj)
	if err != nil {
		log.Fatal(err)
	}

	res, err := uuid.FromBytes(userlib.Hash(marshalled)[:16])
	if err != nil {
		log.Fatal(err)
	}

	return res
}

func encryptStruct(obj interface{}, symKeys SymKeyset) []byte {
	objMarshalled, _ := json.Marshal(obj)
	ciphertext := symKeys.Encrypt(objMarshalled)
	return ciphertext
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

	ciphertext := encryptStruct(privKeyset, symKeys)
	privKeyUUID := toUUID(PrivKeyLocationParams{
		Username: username,
		UserSalt: userSalt,
	})

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
	privksUUID := toUUID(PrivKeyLocationParams{
		Username: username,
		UserSalt: userSalt,
	})
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
	numChunksEncrypted := encryptStruct(1, fileSymKeyset)

	fileChunksUUID := toUUID(fileID)

	dataEncrypted := fileSymKeyset.Encrypt(data)
	dataLocationUUID := toUUID(FileChunkLocationParams{
		FileID: fileID,
		Chunk:  0,
	})

	userlib.DatastoreSet(fileChunksUUID, numChunksEncrypted)
	userlib.DatastoreSet(dataLocationUUID, dataEncrypted)

	filePointer := Pointer{
		ID:   fileID,
		Keys: fileSymKeyset,
	}

	// Create file share hierarchy (root node)
	fileNode := FileNode{
		Username:      u.Username,
		ChildPointers: []Pointer{},
	}

	fileNodeEncrypted := encryptStruct(fileNode, nodeSymKeyset)

	userlib.DatastoreSet(nodeID, fileNodeEncrypted)

	nodePointer := Pointer{
		ID:   nodeID,
		Keys: nodeSymKeyset,
	}

	// Create file directory entry for this user
	fileMeta := FileMeta{
		Owner:       u.Username,
		Filename:    filename,
		FilePointer: filePointer,
		NodePointer: nodePointer,
	}

	fileMetaEncrypted := encryptStruct(fileMeta, u.SymKeys)

	fileDirectoryUUID := toUUID(UserFileDirectoryParams{
		Username: u.Username,
		Filename: filename,
		UserSalt: u.UserSalt,
	})

	userlib.DatastoreSet(fileDirectoryUUID, fileMetaEncrypted)

	return nil
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (u *User) AppendFile(filename string, data []byte) (err error) {
	fileDirectoryUUID := toUUID(UserFileDirectoryParams{
		Username: u.Username,
		Filename: filename,
		UserSalt: u.UserSalt,
	})
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
	fileChunksUUID := toUUID(filePointer.ID)
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
	numChunksEncrypted = encryptStruct(numChunks, filePointer.Keys)

	userlib.DatastoreSet(fileChunksUUID, numChunksEncrypted)

	// Save new chunk
	dataEncrypted := filePointer.Keys.Encrypt(data)
	dataLocationUUID := toUUID(FileChunkLocationParams{
		FileID: filePointer.ID,
		Chunk:  numChunks - 1,
	})

	userlib.DatastoreSet(dataLocationUUID, dataEncrypted)

	return nil
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (u *User) LoadFile(filename string) (dataBytes []byte, err error) {
	userFileDirectoryParamsUUID := toUUID(UserFileDirectoryParams{
		Username: u.Username,
		Filename: filename,
		UserSalt: u.UserSalt,
	})

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
	fileChunksUUID := toUUID(filePointer.ID)

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
		dataLocationUUID := toUUID(FileChunkLocationParams{
			FileID: filePointer.ID,
			Chunk:  i,
		})

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
func (u *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	// Fetch file metadata
	fileDirectoryUUID := toUUID(UserFileDirectoryParams{
		Username: u.Username,
		Filename: filename,
		UserSalt: u.UserSalt,
	})
	fileMetaEncrypted, ok := userlib.DatastoreGet(fileDirectoryUUID)

	if !ok {
		return uuid.Nil, errors.New("file not found")
	}

	fileMetaBytes, err := u.SymKeys.Decrypt(fileMetaEncrypted)

	if err != nil {
		return uuid.Nil, err
	}

	var fileMeta FileMeta
	json.Unmarshal(fileMetaBytes, &fileMeta)

	// Revocation check
	access, err := fileMeta.RevocationCheck(*u)
	if !access {
		return uuid.Nil, errors.New("you no longer have access to this file")
	}

	if err != nil {
		return uuid.Nil, errors.New("cannot verify/decrypt revocation notice")
	}

	// Get recipient public key
	recipientEKey, ok := userlib.KeystoreGet(recipient + "_e")
	if !ok {
		return uuid.Nil, errors.New("cannot get recipient public key")
	}

	// Create child node in hierarchy
	childUUID := uuid.New()
	childSymKeyset := SymKeyset{
		EKey: userlib.RandomBytes(16),
		MKey: userlib.RandomBytes(16),
	}

	childNode := FileNode{
		Username:      recipient,
		ChildPointers: []Pointer{},
	}

	childNodeEncrypted := encryptStruct(childNode, childSymKeyset)

	userlib.DatastoreSet(childUUID, childNodeEncrypted)

	// Add pointer from our node to new node
	ourNodeEncrypted, ok := userlib.DatastoreGet(fileMeta.NodePointer.ID)
	if !ok {
		return uuid.Nil, errors.New("cannot access file share hierarchy")
	}

	ourNodeBytes, err := fileMeta.NodePointer.Keys.Decrypt(ourNodeEncrypted)
	if err != nil {
		return uuid.Nil, errors.New("cannot decrypt file share hierarchy")
	}

	var ourNode FileNode
	json.Unmarshal(ourNodeBytes, &ourNode)

	ourNode.ChildPointers = append(ourNode.ChildPointers, Pointer{
		ID:   childUUID,
		Keys: childSymKeyset,
	})

	ourNodeEncrypted = encryptStruct(ourNode, fileMeta.NodePointer.Keys)

	userlib.DatastoreSet(fileMeta.NodePointer.ID, ourNodeEncrypted)

	// Generate temp key, encrypted file meta, etc.
	theirMeta := FileMeta{
		Owner:       fileMeta.Owner,
		Filename:    "",
		FilePointer: fileMeta.FilePointer,
		NodePointer: Pointer{
			ID:   childUUID,
			Keys: childSymKeyset,
		},
	}

	tempKeyset := SymKeyset{
		EKey: userlib.RandomBytes(16),
		MKey: userlib.RandomBytes(16),
	}

	theirMetaEncrypted := encryptStruct(theirMeta, tempKeyset)
	tempKeysetMarshalled, _ := json.Marshal(tempKeyset)
	tempKeysetEncrypted := PubEncrypt(recipientEKey, u.PrivKeys.SKey, tempKeysetMarshalled)

	accessInfoMarshalled, _ := json.Marshal(AccessTokenInfo{
		SymKeyCipher:   tempKeysetEncrypted,
		FileMetaCipher: theirMetaEncrypted,
	})

	accessTokenUUID := uuid.New()
	userlib.DatastoreSet(accessTokenUUID, accessInfoMarshalled)

	return accessTokenUUID, nil
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (u *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {

	if !userExists(u.Username) {
		return errors.New("invalid credentials")
	}

	// Get owner DS verification key
	VKey, ok := userlib.KeystoreGet(sender + "_v")
	if !ok {
		return errors.New("cannot get verification key for file owner to verify revocation notice")
	}

	// Decrypt and verify access token info
	accessTokenInfoBytes, ok := userlib.DatastoreGet(accessToken)

	if !ok {
		return errors.New("failed to retrive access token info")
	}

	var accessTokenInfo AccessTokenInfo
	json.Unmarshal(accessTokenInfoBytes, &accessTokenInfo)

	tempSymKeyBytes, err := PubDecrypt(u.PrivKeys.DKey, VKey, accessTokenInfo.SymKeyCipher)

	var tempSymKey SymKeyset
	json.Unmarshal(tempSymKeyBytes, &tempSymKey)

	if err != nil {
		return err
	}

	fileMetaBytes, err := tempSymKey.Decrypt(accessTokenInfo.FileMetaCipher)

	if err != nil {
		return err
	}

	var fileMeta FileMeta
	json.Unmarshal(fileMetaBytes, &fileMeta)

	// Update file directory entry for this user
	fileMeta.Filename = filename

	fileMetaEncrypted := encryptStruct(fileMeta, u.SymKeys)

	fileDirectoryUUID := toUUID(UserFileDirectoryParams{
		Username: u.Username,
		Filename: filename,
		UserSalt: u.UserSalt,
	})

	userlib.DatastoreSet(fileDirectoryUUID, fileMetaEncrypted)

	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (u *User) RevokeFile(filename string, targetUsername string) (err error) {
	// Fetch file metadata
	fileDirectoryUUID := toUUID(UserFileDirectoryParams{
		Username: u.Username,
		Filename: filename,
		UserSalt: u.UserSalt,
	})
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

	// Revocation check
	access, err := fileMeta.RevocationCheck(*u)
	if !access {
		return errors.New("you no longer have access to this file")
	}

	if err != nil {
		return errors.New("cannot verify/decrypt revocation notice")
	}

	// Check that we are owner
	if fileMeta.Owner != u.Username {
		return errors.New("non-owner user trying to revoke file access")
	}

	filePointer := fileMeta.FilePointer

	// Read and write to new location
	fileChunksUUID := toUUID(filePointer.ID)

	// retrieve the number of file chunks from the datastore
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

	// delete the old number of file chunks from the datastore
	userlib.DatastoreDelete(fileChunksUUID)

	fileData := []byte{}

	// delete the old file chunks while compressing the file data into new array
	for i := 0; i < numChunks; i++ {
		dataLocationUUID := toUUID(FileChunkLocationParams{
			FileID: filePointer.ID,
			Chunk:  i,
		})

		// retrieve the encrypted file chunk data from the datastore
		ciphertext, ok := userlib.DatastoreGet(dataLocationUUID)

		if !ok {
			return errors.New("failed to retrieve file chunk")
		}

		fileDataChunk, err := filePointer.Keys.Decrypt(ciphertext)

		if err != nil {
			return err
		}

		// concat the file chunks
		fileData = append(fileData, fileDataChunk...)

		// clear the existing data at the old location
		userlib.DatastoreDelete(dataLocationUUID)
	}

	// Generate new file Pointer
	newFileID := uuid.New()
	newSymKeySet := SymKeyset{
		EKey: userlib.RandomBytes(16),
		MKey: userlib.RandomBytes(16),
	}

	newPointer := Pointer{
		ID:   newFileID,
		Keys: newSymKeySet,
	}

	// store all chunks as a single chunk (may approach this again later)
	newNumChunksEncrypted := encryptStruct(1, newSymKeySet)

	newDataEncrypted := newSymKeySet.Encrypt(fileData)

	newFileChunksUUID := toUUID(newFileID)
	newDataLocationUUID := toUUID(FileChunkLocationParams{
		FileID: newFileID,
		Chunk:  0,
	})

	userlib.DatastoreSet(newFileChunksUUID, newNumChunksEncrypted)
	userlib.DatastoreSet(newDataLocationUUID, newDataEncrypted)

	// Create revocation notices by traversing hierarchy
	newPointerBytes, _ := json.Marshal(newPointer)
	_, err = createRevocationNotice(newPointerBytes, filePointer.ID, fileMeta.NodePointer, u.PrivKeys.SKey, targetUsername)

	if err != nil {
		return errors.New("failed to create revocation notices")
	}

	return nil
}

// Recursively create revocation notices for all users on the hierarchy EXCEPT for revokedUsername
// Returns whether or not the node pointed to should still remain in the hierarchy; if false, should be pruned
func createRevocationNotice(
	newFilePointerBytes []byte,
	oldFileID uuid.UUID,
	fileNodePointer Pointer,
	signingKey userlib.PrivateKeyType,
	revokedUsername string) (bool, error) {
	// Decrypt the file node pointer to a file node
	fileNodeEncrypted, ok := userlib.DatastoreGet(fileNodePointer.ID)
	if !ok {
		return false, errors.New("can't find file node")
	}

	fileNodeBytes, err := fileNodePointer.Keys.Decrypt(fileNodeEncrypted)
	if err != nil {
		return false, err
	}

	var fileNode FileNode
	json.Unmarshal(fileNodeBytes, &fileNode)

	// Check the user corresponding to this node should have access revoked
	if fileNode.Username == revokedUsername {
		return false, nil
	}

	// Create a revocation notice for this node's corresponding user
	revocationNoticeUUID := toUUID(RevocationNoticeLocationParams{
		FileID:   oldFileID,
		Username: fileNode.Username,
	})

	EKey, ok := userlib.KeystoreGet(fileNode.Username + "_e")
	if !ok {
		return false, errors.New("can't find pubkey of user to create revocation notice")
	}

	userlib.DatastoreSet(revocationNoticeUUID, PubEncrypt(EKey, signingKey, newFilePointerBytes))

	// Recurse on children; iterate through list backwards so we can delete children as we go w/o worry
	for i := len(fileNode.ChildPointers) - 1; i >= 0; i-- {
		keep, err := createRevocationNotice(newFilePointerBytes, oldFileID, fileNode.ChildPointers[i], signingKey, revokedUsername)
		if err != nil {
			return false, err
		}

		if !keep {
			// Remove this child from child pointers
			fileNode.ChildPointers = append(fileNode.ChildPointers[:i], fileNode.ChildPointers[i+1:]...)
		}
	}

	// Update fileNode
	fileNodeEncrypted = encryptStruct(fileNode, fileNodePointer.Keys)
	userlib.DatastoreSet(fileNodePointer.ID, fileNodeEncrypted)

	return true, nil
}

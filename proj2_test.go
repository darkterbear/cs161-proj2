package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func getKeyset(m *map[uuid.UUID][]byte) map[uuid.UUID]bool {
	keyset := make(map[uuid.UUID]bool)
	for k := range *m {
		keyset[k] = true
	}
	return keyset
}

func setDiff(s1 *map[uuid.UUID]bool, s2 *map[uuid.UUID]bool) []uuid.UUID {
	res := []uuid.UUID{}
	for k := range *s1 {
		if val, ok := (*s2)[k]; !(ok && val) {
			// k is in s1 but not in s2, add to res
			res = append(res, k)
		}
	}
	return res
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestDuplicateStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	err1 := u.StoreFile("file1", []byte("This is a test"))
	err2 := u.StoreFile("file1", []byte("This is a different test"))

	if !(err1 == nil && err2 != nil) {
		t.Error("Failed to prevent duplicate file stores")
		return
	}
}

func TestTamperedFileDirectory(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	datastore := userlib.DatastoreGetMap()
	keyset1 := getKeyset(&datastore)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	keyset2 := getKeyset(&datastore)
	diff := setDiff(&keyset2, &keyset1)
	datastore[diff[0]][0] = 0

	_, err2 := u.LoadFile("file1")
	if err2 == nil {
		t.Error("No error when accessing a file whose file directory entry has been tampered with", err2)
		return
	}
}

// func TestTamperedFileData(t *testing.T) {
// 	clear()
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	datastore := userlib.DatastoreGetMap()

// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	fileDirectoryUUID := toUUIDTesting(UserFileDirectoryParamsTesting{
// 		Username: u.Username,
// 		Filename: "file1",
// 		UserSalt: u.UserSalt,
// 	})

// 	var fm FileMetaTesting
// 	decryptToStructTesting(datastore[fileDirectoryUUID], u.SymKeys, &fm)

// 	datastore[toUUIDTesting(fm.FilePointer.ID)][0] = 0

// 	_, err2 := u.LoadFile("file1")
// 	if err2 == nil {
// 		t.Error("No error when accessing a file whose file data has been tampered with", err2)
// 		return
// 	}
// }

// func TestTamperedFileData2(t *testing.T) {
// 	clear()
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	datastore := userlib.DatastoreGetMap()

// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	fileDirectoryUUID := toUUIDTesting(UserFileDirectoryParamsTesting{
// 		Username: u.Username,
// 		Filename: "file1",
// 		UserSalt: u.UserSalt,
// 	})

// 	var fm FileMetaTesting
// 	decryptToStructTesting(datastore[fileDirectoryUUID], u.SymKeys, &fm)

// 	datastore[toUUIDTesting(FileChunkLocationParams{
// 		FileID: fm.FilePointer.ID,
// 		Chunk:  0,
// 	})][0] = 0

// 	_, err2 := u.LoadFile("file1")
// 	if err2 == nil {
// 		t.Error("No error when accessing a file whose file data has been tampered with", err2)
// 		return
// 	}
// }

// func TestAppendTamperedChunks(t *testing.T) {
// 	clear()
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	datastore := userlib.DatastoreGetMap()

// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	fileDirectoryUUID := toUUIDTesting(UserFileDirectoryParamsTesting{
// 		Username: u.Username,
// 		Filename: "file1",
// 		UserSalt: u.UserSalt,
// 	})

// 	var fm FileMetaTesting
// 	decryptToStructTesting(datastore[fileDirectoryUUID], u.SymKeys, &fm)

// 	datastore[toUUIDTesting(fm.FilePointer.ID)][0] = 0

// 	err = u.AppendFile("file1", []byte("This is another test"))
// 	if err == nil {
// 		t.Error("No error when apending to a file whose file chunk count data has been tampered with", err)
// 		return
// 	}
// }

// func TestInvalidFile(t *testing.T) {
// 	clear()
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	_, err2 := u.LoadFile("this file does not exist")
// 	if err2 == nil {
// 		t.Error("Downloaded a ninexistent file", err2)
// 		return
// 	}
// }

// func TestShare(t *testing.T) {
// 	clear()
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}
// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}

// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	var v2 []byte
// 	var accessToken uuid.UUID

// 	v, err = u.LoadFile("file1")
// 	if err != nil {
// 		t.Error("Failed to download the file from alice", err)
// 		return
// 	}

// 	accessToken, err = u.ShareFile("file1", "bob")
// 	if err != nil {
// 		t.Error("Failed to share the a file", err)
// 		return
// 	}
// 	err = u2.ReceiveFile("file2", "alice", accessToken)
// 	if err != nil {
// 		t.Error("Failed to receive the share message", err)
// 		return
// 	}

// 	v2, err = u2.LoadFile("file2")
// 	if err != nil {
// 		t.Error("Failed to download the file after sharing", err)
// 		return
// 	}
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Shared file is not the same", v, v2)
// 		return
// 	}
// }

// // Student tests
// func TestAppend(t *testing.T) {
// 	clear()

// 	// init Alice
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	// Create and store file1
// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	// Test load file1
// 	v2, err2 := u.LoadFile("file1")
// 	if err2 != nil {
// 		t.Error("Failed to upload and download", err2)
// 		return
// 	}
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Downloaded file is not the same", v, v2)
// 		return
// 	}

// 	a := []byte("This is an append")

// 	// Append to file1
// 	err3 := u.AppendFile("file1", a)

// 	if err3 != nil {
// 		t.Error("Failed to append to file", err3)
// 	}

// 	v3, err4 := u.LoadFile("file1")
// 	if err4 != nil {
// 		t.Error("Failed to upload and download", err4)
// 		return
// 	}

// 	// Test if file has been correctly appended to
// 	v = append(v, a...)
// 	if !reflect.DeepEqual(v, v3) {
// 		t.Error("Downloaded appended file is not the same", v, v3)
// 		return
// 	}
// }

// func TestRevoke(t *testing.T) {
// 	clear()

// 	// init Alice
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	// init Bob
// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}

// 	// Create and store file1
// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	var v2 []byte
// 	var accessToken uuid.UUID

// 	// Test load file1
// 	v, err = u.LoadFile("file1")
// 	if err != nil {
// 		t.Error("Failed to download the file from alice", err)
// 		return
// 	}

// 	// Test share + receive actions
// 	accessToken, err = u.ShareFile("file1", "bob")
// 	if err != nil {
// 		t.Error("Failed to share the a file", err)
// 		return
// 	}
// 	err = u2.ReceiveFile("file2", "alice", accessToken)
// 	if err != nil {
// 		t.Error("Failed to receive the share message", err)
// 		return
// 	}

// 	v2, err = u2.LoadFile("file2")
// 	if err != nil {
// 		t.Error("Failed to download the file after sharing", err)
// 		return
// 	}
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Shared file is not the same", v, v2)
// 		return
// 	}

// 	// Test revoke file1 from Bob
// 	err = u.RevokeFile("file1", "bob")
// 	if err != nil {
// 		t.Error("Failed to revoke file from bob", err)
// 	}

// 	// Test load file1 after revoke

// 	// Alice should be able to load file
// 	_, err = u.LoadFile("file1")
// 	if err != nil {
// 		t.Error("Failed to download the file from alice", err)
// 		return
// 	}

// 	// Bob should not be able to load file
// 	_, err = u.LoadFile("file2")
// 	if err == nil {
// 		t.Error("Bob should not be able to access file after being revoked by Alice", err)
// 		return
// 	}
// }

// func TestRevokeNonOwnedFile(t *testing.T) {
// 	clear()

// 	// init Alice
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	// init Bob
// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}

// 	// Create and store file1
// 	v := []byte("This is a test")
// 	u.StoreFile("file1", v)

// 	var accessToken uuid.UUID

// 	// Test load file1
// 	v, err = u.LoadFile("file1")
// 	if err != nil {
// 		t.Error("Failed to download the file from alice", err)
// 		return
// 	}

// 	// Test share + receive actions
// 	accessToken, err = u.ShareFile("file1", "bob")
// 	if err != nil {
// 		t.Error("Failed to share the a file", err)
// 		return
// 	}
// 	err = u2.ReceiveFile("file2", "alice", accessToken)
// 	if err != nil {
// 		t.Error("Failed to receive the share message", err)
// 		return
// 	}

// 	err = u2.RevokeFile("file2", "alice")
// 	if err == nil {
// 		t.Error("U2 was allowed to revoke a file owned by U1")
// 	}
// }

// func TestRepeatInit(t *testing.T) {
// 	clear()
// 	_, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	u, err := InitUser("alice", "boo")
// 	expectedError := "username already exists"

// 	if u != nil {
// 		t.Error("Initilized a duplicate user", err)
// 		return
// 	} else if err.Error() != expectedError {
// 		t.Error("Unexpected error", err)
// 		return
// 	}
// }

// func TestGetUser(t *testing.T) {
// 	clear()

// 	u1, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	u2, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to get user", err)
// 		return
// 	}

// 	if !reflect.DeepEqual(u1, u2) {
// 		t.Error("Initialized and retrieved user are different", u1, u2)
// 		return
// 	}
// }

// func TestGetUserInvalidUsername(t *testing.T) {
// 	clear()
// 	_, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	u2, err := GetUser("bob", "fubar")

// 	if u2 != nil {
// 		t.Error("Grabbed a user with invalid username)", err)
// 	}
// }

// func TestGetUserInvalidPassword(t *testing.T) {
// 	clear()
// 	_, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	u2, err := GetUser("alice", "boo")
// 	if u2 != nil {
// 		t.Error("Grabbed a user with invalid password", err)
// 	}
// }
// func TestTamperedGetUser(t *testing.T) {
// 	clear()
// 	u1, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	datastore := userlib.DatastoreGetMap()

// 	privksUUID := toUUIDTesting(PrivKeyLocationParamsTesting{
// 		Username: u1.Username,
// 		UserSalt: u1.UserSalt,
// 	})
// 	datastore[privksUUID][0] = 0

// 	_, err = GetUser("alice", "fubar")
// 	if err == nil {
// 		t.Error("GetUser succeeded on tampered private key storage", err)
// 	}
// }
// func TestAppendInvalidFile(t *testing.T) {
// 	clear()

// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}
// 	err = u.AppendFile("file", nil)
// 	expectedError := "file not found"

// 	if err.Error() != expectedError {
// 		t.Error("Unexpected error", err)
// 		return
// 	}
// }

// func TestShareInvalidFile(t *testing.T) {
// 	clear()

// 	u1, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	_, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}

// 	accessToken, err := u1.ShareFile("file", "bob")
// 	expectedError := "file not found"

// 	if accessToken != uuid.Nil {
// 		t.Error("Access token created for invalid file", err)
// 		return
// 	} else if err.Error() != expectedError {
// 		t.Error("Unexpected error", err)
// 		return
// 	}
// }

// func TestShareInvalidRecipient(t *testing.T) {
// 	clear()

// 	u1, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	v := []byte("This is a test")
// 	u1.StoreFile("file1", v)

// 	accessToken, err := u1.ShareFile("file1", "bob")
// 	expectedError := "cannot get recipient public key"

// 	if accessToken != uuid.Nil {
// 		t.Error("Access token created for invalid user", err)
// 		return
// 	} else if err.Error() != expectedError {
// 		t.Error("Unexpected error", err)
// 		return
// 	}
// }

// func TestShareTamperedHierarchy(t *testing.T) {
// 	clear()

// 	u1, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	v := []byte("This is a test")
// 	u1.StoreFile("file1", v)

// 	datastore := userlib.DatastoreGetMap()
// 	fileDirectoryUUID := toUUIDTesting(UserFileDirectoryParamsTesting{
// 		Username: u1.Username,
// 		Filename: "file1",
// 		UserSalt: u1.UserSalt,
// 	})

// 	var fm FileMetaTesting
// 	decryptToStructTesting(datastore[fileDirectoryUUID], u1.SymKeys, &fm)

// 	datastore[fm.NodePointer.ID][0] = 0

// 	_, err = u1.ShareFile("file1", "bob")

// 	if err == nil {
// 		t.Error("ShareFile succeeded on file where our hierarchy node was tampered with")
// 		return
// 	}
// }

// func TestReceiveInvalidUser(t *testing.T) {
// 	clear()

// 	u1, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	u2 := new(User)

// 	v := []byte("This is a test")
// 	u1.StoreFile("file1", v)

// 	err = u2.ReceiveFile("file1", "alice", uuid.Nil)

// 	expectedError := "invalid credentials"

// 	if err.Error() != expectedError {
// 		t.Error("Unexpected error", err)
// 		return
// 	}
// }

// func TestReceiveInvalidSender(t *testing.T) {
// 	clear()

// 	u2, err := InitUser("bob", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	err = u2.ReceiveFile("file1", "alice", uuid.Nil)

// 	expectedError := "cannot get verification key for file owner to verify revocation notice"

// 	if err.Error() != expectedError {
// 		t.Error("Unexpected error", err)
// 		return
// 	}
// }

// func TestReceiveInvalidAccessToken(t *testing.T) {
// 	clear()

// 	u1, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}

// 	v := []byte("This is a test")
// 	u1.StoreFile("file1", v)

// 	u1.ShareFile("file1", "bob")

// 	err = u2.ReceiveFile("file1", "alice", uuid.Nil)

// 	expectedError := "failed to retrive access token info"

// 	if err.Error() != expectedError {
// 		t.Error("Unexpected error", err)
// 		return
// 	}
// }

// func TestReceiverDuplicateFile(t *testing.T) {
// 	clear()

// 	u1, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}

// 	v := []byte("This is a test")
// 	u1.StoreFile("file1", v)
// 	u2.StoreFile("file2", v)

// 	accessToken, _ := u1.ShareFile("file1", "bob")

// 	err = u2.ReceiveFile("file2", "alice", accessToken)

// 	expectedError := "cannot receive file into filename that already exists"

// 	if err.Error() != expectedError {
// 		t.Error("Unexpected error", err)
// 		return
// 	}
// }

// func TestRevokeInvalidFile(t *testing.T) {
// 	clear()

// 	u1, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to initialize user", err)
// 		return
// 	}

// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 		return
// 	}

// 	v := []byte("This is a test")
// 	u1.StoreFile("file1", v)

// 	accessToken, _ := u1.ShareFile("file1", "bob")

// 	_ = u2.ReceiveFile("file2", "alice", accessToken)

// 	err = u1.RevokeFile("bad", "bob")

// }

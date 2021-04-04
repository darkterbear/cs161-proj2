package proj2

type SymKeyset struct {
	EKey []byte // Encryption key
	MKey []byte // MAC key
}

func (sks SymKeyset) Encrypt(plaintext []byte) []byte {
	// TODO: Implement
	return []byte{}
}

func (sks SymKeyset) Decrypt(ciphertext []byte) []byte {
	// TODO: Implement
	return []byte{}
}

type PubKeyset struct {
	EKey []byte // PKE encryption key
	VKey []byte // PKS verification key
}

func (pks PubKeyset) Encrypt(plaintext []byte) []byte {
	// TODO: Implement
	return []byte{}
}

func (pks PubKeyset) Decrypt(ciphertext []byte) []byte {
	// TODO: Implement
	return []byte{}
}

type PrivKeyset struct {
	DKey []byte // PKE decryption key
	SKey []byte // PKS signing key
}

func (pks PrivKeyset) Encrypt(plaintext []byte) []byte {
	// TODO: Implement
	return []byte{}
}

func (pks PrivKeyset) Sign(msg []byte) []byte {
	// TODO: Implement
	return []byte{}
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

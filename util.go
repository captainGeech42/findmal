package main

// HashIsSHA256 returns true if the hash is 64 chars long
func HashIsSHA256(hash string) bool {
	return len(hash) == 64
}

// HashIsSHA1 returns true if the hash is 40 chars long
func HashIsSHA1(hash string) bool {
	return len(hash) == 40
}

// HashIsMD5 returns true if the hash is 32 chars long
func HashIsMD5(hash string) bool {
	return len(hash) == 32
}

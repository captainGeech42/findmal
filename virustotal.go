package main

import (
	"fmt"
)

// VirusTotal struct implementation
type VirusTotal struct {
	MalwareSource
}

// FindFile implementation for VT
func (src *VirusTotal) FindFile(hash string) {
	src.HasFile = true
	fmt.Printf("Found hash on VT: %s\n", hash)
}

// DownloadFile implementation for VT
// Not able to download files
func (src *VirusTotal) DownloadFile(hash string) {
	src.HasFile = false
	return
}

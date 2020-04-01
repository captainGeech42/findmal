package main

import (
	"flag"
	"fmt"
	"os"
)

// https://stackoverflow.com/a/31873508
func usage() {
	fmt.Printf("Usage: %s [OPTIONS] hash1 [hash2 [hash3 [...]]]\n", os.Args[0])
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func main() {
	fmt.Println("Hello world!")

	downloadParam := flag.Bool("download", false, "Download malware sample (if found)")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
	}

	fmt.Printf("Download? %v\n", *downloadParam)
	fmt.Println(flag.Args())
}

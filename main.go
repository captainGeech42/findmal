package main

import (
	"flag"
	"fmt"
	"os"
)

// https://dev.to/llinaresvicent/polymorphism-golang-slices-3jcj
var sources []MalwareSourcer

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
		os.Exit(1)
	}

	fmt.Printf("Download? %v\n", *downloadParam)
	fmt.Println(flag.Args())

	addSources()

	for _, hash := range flag.Args() {
		for _, src := range sources {
			src.FindFile(hash)
			fmt.Println(src.GetHasFile())
			src.DownloadFile(hash)
			fmt.Println(src.GetHasFile())
		}
	}
}

func addSources() {
	sources = append(sources, &VirusTotal{})
}

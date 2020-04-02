package main

import (
	"flag"
	"fmt"
	"os"
)

var sources []MalwareSourcer
var config map[string]interface{}

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

	config = loadConfig()

	addSources()

	for _, hash := range flag.Args() {
		// duplicate the master source list so we can properly track the source states for each hash
		sourcesForHash := make([]MalwareSourcer, len(sources))
		copy(sourcesForHash, sources)

		for _, src := range sources {
			src.FindFile(hash)
			fmt.Println(src.GetHasFile())
			src.DownloadFile(hash)
			fmt.Println(src.GetHasFile())
		}
	}
}

func addSources() {
	if configHasKey("VT_API_KEY") {
		sources = append(sources, &VirusTotal{})
	}
}

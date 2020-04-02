package main

import (
	"flag"
	"fmt"
	"log"
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
	downloadParam := flag.Bool("download", false, "Download malware sample (if found)")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	config = loadConfig()

	addSources()
	log.Printf("Loaded %d malware source(s)\n", len(sources))

	for _, hash := range flag.Args() {
		// duplicate the master source list so we can properly track the source states for each hash
		sourcesForHash := make([]MalwareSourcer, len(sources))
		copy(sourcesForHash, sources)

		// track if downloaded yet
		downloaded := false

		for _, src := range sources {
			log.Printf("Searching %s for %s\n", src.GetName(), hash)
			src.FindFile(hash)

			if src.GetHasFile() {
				log.Printf("%s has %s\n", src.GetName(), hash)
			}

			// download the file iff user wants downloads, we haven't downloaded this file,
			// and we can download from this source
			if *downloadParam && !downloaded && src.GetCanDownload() {
				log.Printf("Downloading %s from %s\n", hash, src.GetName())
				src.DownloadFile(hash)
				downloaded = true
			}
		}
	}
}

func addSources() {
	if configHasKey("VT_API_KEY") {
		sources = append(sources, &VirusTotal{MalwareSource{Name: "VirusTotal"}})
	}

	if configHasKey("HA_API_KEY") {
		sources = append(sources, &HybridAnalysis{MalwareSource{Name: "Hybrid Analysis"}})
	}
}

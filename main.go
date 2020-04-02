package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var sources []MalwareSourcer
var config map[string]interface{}
var results []SearchResult

// https://stackoverflow.com/a/31873508
func usage() {
	fmt.Printf("Usage: %s [OPTIONS] hash1 [hash2 [hash3 [...]]]\n", os.Args[0])
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func main() {
	// handle arguments
	downloadParam := flag.Bool("download", false, "Download malware sample (if found)")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// load JSON config (from ~/.config/findmal.json or ./findmal.json)
	config = loadConfig()

	// load malware sources based on config
	addSources()
	log.Printf("Loaded %d malware source(s)\n", len(sources))

	// search/download all hashes
	for _, hash := range flag.Args() {
		// duplicate the master source list so we can properly track the source states for each hash
		sourcesForHash := make([]MalwareSourcer, len(sources))
		copy(sourcesForHash, sources)

		// store result info
		result := SearchResult{Hash: hash}

		// search/download our file on our sources
		for _, src := range sources {
			log.Printf("Searching %s for %s\n", src.GetName(), hash)
			src.FindFile(hash)

			// source has file
			if src.GetHasFile() {
				log.Printf("%s has %s\n", src.GetName(), hash)
				result.URLs = append(result.URLs, src.GetURL())
			}

			// download the file iff user wants downloads, we haven't downloaded this file,
			// and we can download from this source
			if *downloadParam && !result.Downloaded && src.GetCanDownload() {
				log.Printf("Downloading %s from %s\n", hash, src.GetName())
				src.DownloadFile(hash)
				result.Downloaded = true
			}
		}

		// save result info
		results = append(results, result)
	}

	// print output for user
	for _, r := range results {
		fmt.Printf("\n======= Results for %s =======\n", r.Hash)

		if len(r.URLs) == 0 {
			fmt.Println("Sample not found at any of the configured sources")
			continue
		}

		fmt.Printf("Analysis info available at the following URLs:\n")
		for _, url := range r.URLs {
			fmt.Printf("\t%s\n", url)
		}

		if r.Downloaded {
			fmt.Printf("Sample was downloaded to %s.bin\n", r.Hash)
		}
	}
}

func addSources() {
	// VirusTotal
	if configHasKey("VT_API_KEY") {
		sources = append(sources, &VirusTotal{MalwareSource{Name: "VirusTotal"}})
	}

	// Hybrid Analysis
	if configHasKey("HA_API_KEY") {
		sources = append(sources, &HybridAnalysis{MalwareSource{Name: "Hybrid Analysis"}})
	}
}

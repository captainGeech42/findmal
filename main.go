package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var sources []MalwareSourcer
var config map[string]interface{}
var downloadSamples bool

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
	downloadSamples = *downloadParam

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// load JSON config (from ~/.config/findmal.json or ./findmal.json)
	config = loadConfig()

	// load malware sources based on config
	addSources()
	log.Printf("Loaded %d malware source(s)\n", len(sources))

	results := getSamples(flag.Args())
	printResults(results)
}

// Add sources that support any hash type first, then the specific ones
func addSources() {
	// VirusTotal
	if configHasKey("VT_API_KEY") {
		sources = append(sources, &VirusTotal{MalwareSource{Name: "VirusTotal"}})
	}

	// MalwareBazaar
	if configHasKey("MB_API_KEY") {
		sources = append(sources, &MalwareBazaar{MalwareSource{Name: "MalwareBazaar"}})
	}

	// Hybrid Analysis
	// SHA256 only
	if configHasKey("HA_API_KEY") {
		sources = append(sources, &HybridAnalysis{MalwareSource{Name: "Hybrid Analysis"}})
	}
}

func getSamples(hashes []string) []SearchResult {
	var results []SearchResult

	// search/download all hashes
	for _, hash := range hashes {
		// duplicate the master source list so we can properly track the source states for each hash
		sourcesForHash := make([]MalwareSourcer, len(sources))
		copy(sourcesForHash, sources)

		// store result info
		result := SearchResult{Sample: Sample{UserHash: hash}}
		switch len(hash) {
		case 32:
			result.Sample.MD5 = hash
		case 40:
			result.Sample.SHA1 = hash
		case 64:
			result.Sample.SHA256 = hash
		default:
			log.Printf("%s is an invalid hash, skipping", hash)
			continue
		}

		// search/download our file on our sources
		for _, src := range sources {
			log.Printf("Searching %s for %s\n", src.GetName(), hash)
			src.FindFile(&result.Sample)

			// source has file
			if src.GetHasFile() {
				log.Printf("%s has %s\n", src.GetName(), hash)
				result.URLs = append(result.URLs, src.GetURL())
			}

			// download the file iff user wants downloads, we haven't downloaded this file,
			// and we can download from this source
			if downloadSamples && !result.Downloaded && src.GetCanDownload() {
				log.Printf("Downloading %s from %s\n", hash, src.GetName())
				ok := src.DownloadFile(result.Sample)
				if ok {
					log.Printf("Successfully downloaded %s from %s\n", hash, src.GetName())
				}
				result.Downloaded = ok
			}
		}

		// save result info
		results = append(results, result)
	}

	return results
}

func printResults(results []SearchResult) {
	// print output for user
	for _, r := range results {
		fmt.Printf("\n======= Results for %s =======\n", r.Sample.UserHash)

		if len(r.URLs) == 0 {
			fmt.Println("Sample not found at any of the configured sources")
			continue
		}

		var md5 string
		if r.Sample.MD5 == "" {
			md5 = "<unknown>"
		} else {
			md5 = r.Sample.MD5
		}
		var sha1 string
		if r.Sample.SHA1 == "" {
			sha1 = "<unknown>"
		} else {
			sha1 = r.Sample.SHA1
		}
		var sha256 string
		if r.Sample.SHA256 == "" {
			sha256 = "<unknown>"
		} else {
			sha256 = r.Sample.SHA256
		}

		fmt.Println("Sample Info:")
		fmt.Printf("\tMD5: %s\n", md5)
		fmt.Printf("\tSHA1: %s\n", sha1)
		fmt.Printf("\tSHA256: %s\n", sha256)

		fmt.Printf("Analysis info available at the following URLs:\n")
		for _, url := range r.URLs {
			fmt.Printf("\t%s\n", url)
		}

		if r.Downloaded {
			fmt.Printf("Sample was downloaded to %s.bin\n", r.Sample.UserHash)
		} else if downloadSamples {
			fmt.Println("Unable to download sample as requested (see log above for more details)")
		}
	}
}

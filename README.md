# findmal
[![Go Report Card](https://goreportcard.com/badge/github.com/captainGeech42/findmal)](https://goreportcard.com/report/github.com/captainGeech42/findmal)

A tool to find/download malware samples from various public repositories

## Install

1. `go get github.com/captainGeech42/findmal`
2. Copy `config.ex.json` to `~/.config/findmal.json`
    - If `~/.config/findmal.json` isn't found, `findmal` will also check your current directory for a `findmal.json` file.
3. Fill in the appropriate API keys

## Usage
```
$ findmal 
Usage: findmal [OPTIONS] hash1 [hash2 [hash3 [...]]]
Options:
  -download
        Download malware sample (if found)
```

Sample commands:
```
# search for 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85
$ findmal 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85

# search/download 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85
$ findmal -download 8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85

# search for hash[1,2,3]
$ findmal hash1 hash2 hash3

# search for and download hash[1,2,3]
$ findmal -download hash1 hash2 hash3
```

You can provide a MD5, SHA1, or a SHA256 (or some combination).

## Where are my API keys, and where do I put them?

### VirusTotal
Sign in to [VirusTotal](https://www.virustotal.com/), click on your name (top-right corner), select `API key`.

Put your key in the config file as the `VT_API_KEY` value.
# findmal
[![Go Report Card](https://goreportcard.com/badge/github.com/captainGeech42/findmal)](https://goreportcard.com/report/github.com/captainGeech42/findmal)

A tool to find/download malware samples from various public repositories

Currently supports:

* VirusTotal (search only)
* Hybrid Analysis (search only, download coming soon)
* MalwareBazaar

In the future, will (probably) support:

* VirusShare
* VirusBay
* CAPE Sandbox (the public one)
* Intezer Analyze

Unsupported:

* any.run (requires paid API)

## Install
1. `go get github.com/captainGeech42/findmal`
2. Copy `config.ex.json` to `~/.config/findmal.json`
    - If `~/.config/findmal.json` isn't found, `findmal` will also check your current directory for a `findmal.json` file.
3. Fill in the appropriate API keys

If you don't have API access and/or wish to not use a source, either remove the key from the JSON file or leave the value blank. `findmal` will ignore that source.

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

You can provide a MD5, SHA1, or a SHA256 (or some combination). Please note that not all sources may support all hash types (a message will be printed when attempting to search a source with an invalid hash type)

When downloading a sample (by providing the `-download` argument), the sample is saved to `./[hash].bin`.

## Where are my API keys, and where do I put them?

### VirusTotal
Sign in to [VirusTotal](https://www.virustotal.com/), click on your name (top-right corner), select `API key`.

Put your key in the config file as the `VT_API_KEY` value.

### Hybrid Analysis
Go to your [profile page](https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab) and click `Create API key`.

`findmal` uses the Hybrid Analysis API v2, and only needs the `API Key` value. Put it in as the `HA_API_KEY` value.

In order to download files from Hybrid Analysis, you must be a 'vetted' researcher. You can start the vetting process by clicking on `Upgrade API key` on the profile page linked above, and filling out the form.

### MalwareBazaar
Go to your [account page](https://bazaar.abuse.ch/account/), your API key is listed there.

Put your key in the config file as the `MB_API_KEY` value.
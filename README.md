# findmal
[![Go Report Card](https://goreportcard.com/badge/github.com/captainGeech42/findmal)](https://goreportcard.com/report/github.com/captainGeech42/findmal)

A tool to find/download malware samples from various public repositories

Currently supports:

* VirusTotal (search only)
* Hybrid Analysis (search only, download coming soon)
* MalwareBazaar (search only, download coming soon)

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

Example output:
```
$ findmal 8ee9a2f9ec53d863745fda55919d3a0af5265716
[log snipped]

======= Results for 8ee9a2f9ec53d863745fda55919d3a0af5265716 =======
Sample Info:
        MD5: bf2a9c3b5493ce819152f1c3caa67202
        SHA1: 8ee9a2f9ec53d863745fda55919d3a0af5265716
        SHA256: b5c24d94b63f844c5350bedb4312499887b61490b2080a98611c28320c3a7274
Analysis info available at the following URLs:
        https://www.virustotal.com/gui/file/8ee9a2f9ec53d863745fda55919d3a0af5265716/details
        https://bazaar.abuse.ch/sample/b5c24d94b63f844c5350bedb4312499887b61490b2080a98611c28320c3a7274/
        https://www.hybrid-analysis.com/sample/b5c24d94b63f844c5350bedb4312499887b61490b2080a98611c28320c3a7274
```

You can provide a MD5, SHA1, or a SHA256 (or some combination). Please note that not all sources may support all hash types (a message will be printed when attempting to search a source with an invalid hash type). However, if the sample is found on a source, `findmal` will save the MD5, SHA1, and SHA256 for later use on those platforms which only support a certain type.

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
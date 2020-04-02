# findmal
[![Go Report Card](https://goreportcard.com/badge/github.com/captainGeech42/findmal)](https://goreportcard.com/report/github.com/captainGeech42/findmal)

A tool to find/download malware samples from various public repositories

# Install

1. `go get github.com/captainGeech42/findmal`
2. Copy `config.ex.json` to `~/.config/findmal.json`
    - If `~/.config/findmal.json` isn't found, `findmal` will also check your current directory for a `findmal.json` file.
3. Fill in the appropriate API keys

# Where are my API keys, and where do I put them?

## VirusTotal
Sign in to [VirusTotal](https://www.virustotal.com/), click on your name (top-right corner), select `API key`.

Put your key in the config file as the `VT_API_KEY` value.
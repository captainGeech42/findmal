package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// VirusTotal struct implementation
type VirusTotal struct {
	MalwareSource
}

// FindFile implementation for VT
// https://developers.virustotal.com/v3.0/reference#file-info
func (src *VirusTotal) FindFile(hash string) {
	// can't download files from VT, too much $$$, rip
	src.CanDownload = false

	// default not found
	src.HasFile = false

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash), nil)
	req.Header.Add("x-apikey", config["VT_API_KEY"].(string))

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error when contacting VT: " + err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to get bytes from VT response: " + err.Error())
		return
	}

	var jsonDataRaw interface{}
	err = json.Unmarshal(body, &jsonDataRaw)
	if err != nil {
		log.Println("Error parsing JSON data from VT: " + err.Error())
	}
	var jsonData map[string]interface{} = jsonDataRaw.(map[string]interface{})

	// if there is a top level 'data' key, the file exists
	// if there is a top level 'error' key, the file doesn't exist

	if _, ok := jsonData["data"]; ok {
		src.HasFile = true
		src.URL = fmt.Sprintf("https://www.virustotal.com/gui/file/%s/details", hash)
	} else if _, ok := jsonData["error"]; !ok {
		// error key didn't exist
		log.Printf("Got an unknown response from VT")
	}
}

// DownloadFile implementation for VT
// Not able to download files
func (src *VirusTotal) DownloadFile(hash string) {
	return
}

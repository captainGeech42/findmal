package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/tidwall/gjson"
)

// VirusTotal struct implementation
type VirusTotal struct {
	MalwareSource
}

// FindFile implementation for VT
// https://developers.virustotal.com/v3.0/reference#file-info
func (src *VirusTotal) FindFile(sample *Sample) {
	// default not found
	src.HasFile = false

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", sample.UserHash), nil)
	req.Header.Add("x-apikey", config["VT_API_KEY"].(string))

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error when contacting VT: " + err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		log.Println("API request quota for VT has been exceeded")
		return
	}

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
		src.CanDownload = true
		src.URL = fmt.Sprintf("https://www.virustotal.com/gui/file/%s/details", sample.UserHash)

		// save hashes
		// since data is the same, it's ok to overwrite Sample members
		sha256 := strings.Trim(string(gjson.GetBytes(body, "data.attributes.sha256").Raw), "\"")
		sha1 := strings.Trim(string(gjson.GetBytes(body, "data.attributes.sha1").Raw), "\"")
		md5 := strings.Trim(string(gjson.GetBytes(body, "data.attributes.md5").Raw), "\"")
		sample.MD5 = md5
		sample.SHA1 = sha1
		sample.SHA256 = sha256
	} else if _, ok := jsonData["error"]; !ok {
		// error key didn't exist
		log.Printf("Got an unknown response from VT")
	}
}

// DownloadFile implementation for VT
// https://developers.virustotal.com/v3.0/reference#files-download-url
func (src *VirusTotal) DownloadFile(sample Sample) bool {
	// start generating the ZIP file
	postData := []byte(fmt.Sprintf(`{"data":{"password":"infected","hashes":["%s"]}}`, sample.UserHash))
	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://www.virustotal.com/api/v3/intelligence/zip_files", bytes.NewBuffer(postData))
	req.Header.Add("x-apikey", config["VT_API_KEY"].(string))

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error when contacting VT: " + err.Error())
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		log.Println("API key isn't licensed for VT Intelligence")
		return false
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to get bytes from VT response: " + err.Error())
		return false
	}

	zipID := strings.Trim(string(gjson.GetBytes(body, "data.id").Raw), "\"")

	// wait for ZIP file to be ready to download
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/intelligence/zip_files/%s", zipID)
	req, err = http.NewRequest("GET", url, nil)
	req.Header.Add("x-apikey", config["VT_API_KEY"].(string))
	zipReady := false
	for !zipReady {
		resp, err = client.Do(req)
		if err != nil {
			log.Println("Error when contacting VT: " + err.Error())
			return false
		}

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println("Failed to get bytes from VT response: " + err.Error())
			return false
		}

		status := strings.Trim(string(gjson.GetBytes(body, "data.attributes.status").Raw), "\"")
		if status == "finished" {
			zipReady = true
		}
	}

	// download zip file
	req, err = http.NewRequest("GET", fmt.Sprintf("https://www.virustotal.com/api/v3/intelligence/zip_files/%s/download_url", zipID), nil)
	req.Header.Add("x-apikey", config["VT_API_KEY"].(string))
	resp, err = client.Do(req)
	if err != nil {
		log.Println("Error when contacting VT: " + err.Error())
		return false
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to get bytes from VT response: " + err.Error())
		return false
	}

	downloadURL := strings.Trim(string(gjson.GetBytes(body, "data").Raw), "\"")
	req, err = http.NewRequest("GET", downloadURL, nil)
	resp, err = client.Do(req)
	if err != nil {
		log.Println("Error when contacting VT: " + err.Error())
		return false
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to get bytes from VT response: " + err.Error())
		return false
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s.zip", sample.UserHash), body, 0644)
	if err != nil {
		log.Println("Failed to save ZIP from VT to disk: " + err.Error())
		return false
	}
	return true
}

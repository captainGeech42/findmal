package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// HybridAnalysis struct implementation
type HybridAnalysis struct {
	MalwareSource
}

// FindFile implementation for HA
// https://www.hybrid-analysis.com/docs/api/v2#/Analysis_Overview/get_overview__sha256_
func (src *HybridAnalysis) FindFile(hash string) {
	// default not found
	src.CanDownload = false
	src.HasFile = false

	if !HashIsSHA256(hash) {
		log.Printf("Hash type is unsupported, Hybrid Analysis requires SHA256")
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.hybrid-analysis.com/api/v2/overview/%s", hash), nil)
	req.Header.Add("api-key", config["HA_API_KEY"].(string))
	req.Header.Add("User-Agent", "Falcon") // suggested by the API docs to avoid UA blacklists

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error when contacting HA: " + err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// file wasn't found on HA
		src.HasFile = false
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to get bytes from HA response: " + err.Error())
		return
	}

	var jsonDataRaw interface{}
	err = json.Unmarshal(body, &jsonDataRaw)
	if err != nil {
		log.Println("Error parsing JSON data from HA: " + err.Error())
	}
	var jsonData map[string]interface{} = jsonDataRaw.(map[string]interface{})

	// if the top-level key 'sha256' == our hash, file exists
	// if the top-level key 'message' == 'Not Found', file doesn't exist
	// not found already handled by 404 above

	if val := jsonData["sha256"]; val.(string) == hash {
		src.HasFile = true
		src.CanDownload = true
		src.URL = fmt.Sprintf("https://www.hybrid-analysis.com/sample/%s", hash)
	} else {
		log.Printf("Got an unknown response from HA")
	}
}

// DownloadFile implementation for HA
// https://www.hybrid-analysis.com/docs/api/v2#/Sandbox_Report/get_report__id__sample
func (src *HybridAnalysis) DownloadFile(hash string) bool {
	log.Println("Downloading from HA not yet supported")
	return false
}

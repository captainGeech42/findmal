package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/tidwall/gjson"
)

// URLhaus struct implementation
type URLhaus struct {
	MalwareSource
}

// FindFile implementation for URLhaus
// https://urlhaus-api.abuse.ch/#payloadinfo
func (src *URLhaus) FindFile(sample *Sample) {
	// default not found
	src.CanDownload = false
	src.HasFile = false

	// make request
	// urlhaus supports md5 or sha256
	key := ""
	hash := ""
	if sample.MD5!= "" {
		key = "md5_hash"
		hash = sample.MD5
	} else if sample.SHA256 != "" {
		key = "sha256_hash"
		hash = sample.SHA256
	} else {
		log.Println("Hash type is unsupported, URLhaus requires MD5 or SHA256")
		return
	}
	formData := url.Values{
		key: {hash},
	}

	resp, err := http.PostForm("https://urlhaus-api.abuse.ch/v1/payload", formData)
	if err != nil {
		log.Println("Error when contacting URLhaus: " + err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to get bytes from URLhaus response: " + err.Error())
		return
	}

	// parse json response
	var jsonDataRaw interface{}
	err = json.Unmarshal(body, &jsonDataRaw)
	if err != nil {
		log.Println("Error parsing JSON data from URLhaus: " + err.Error())
	}
	var jsonData map[string]interface{} = jsonDataRaw.(map[string]interface{})

	// if the top-level key 'query_status' == 'ok', file exists
	// if the top-level key 'query_status' == 'hash_not_found', file doesn't exist
	queryStatus, ok := jsonData["query_status"]
	if !ok {
		log.Println("Failed to get query_status field in MB response")
		return
	}

	if queryStatus == "ok" {
		src.HasFile = true
		src.CanDownload = true

		// save hashes
		// since data is the same, it's ok to overwrite Sample members
		sha256 := strings.Trim(string(gjson.GetBytes(body, "sha256_hash").Raw), "\"")
		md5 := strings.Trim(string(gjson.GetBytes(body, "md5_hash").Raw), "\"")
		sample.MD5 = md5
		sample.SHA256 = sha256

		src.URL = fmt.Sprintf("https://urlhaus.abuse.ch/browse.php?search=%s", sha256)
	} else if queryStatus == "no_results" {
		// hash not found
		src.CanDownload = false
	} else {
		log.Println("Got an unknown response from URLhaus")
	}
}

// DownloadFile implementation for URLhaus
// https://urlhaus-api.abuse.ch/#download-sample
func (src *URLhaus) DownloadFile(sample Sample) bool {
	// make request
	// FindFile saves the SHA256 so we can safely assume it exists
	resp, err := http.Get(fmt.Sprintf("https://urlhaus-api.abuse.ch/v1/download/%s/", sample.SHA256))
	if err != nil {
		log.Println("Error when contacting URLhaus: " + err.Error())
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to get bytes from URLhaus response: " + err.Error())
		return false
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s.zip", sample.UserHash), body, 0644)
	if err != nil {
		log.Println("Failed to save ZIP from URLhaus to disk: " + err.Error())
		return false
	}
	return true
}

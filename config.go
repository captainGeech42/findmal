package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mitchellh/go-homedir"
)

func loadConfig() map[string]interface{} {
	// try from ~/.config/findmal.json
	path, err := homedir.Expand("~/.config/findmal.json")
	if err != nil {
		fmt.Errorf("failed to get home directory")
		os.Exit(-1)
	}

	var dat []byte
	dat, err = ioutil.ReadFile(path)
	if err != nil {
		// most likely file not found
		// try local directory
		dat, err = ioutil.ReadFile("./findmal.json")

		if err != nil {
			// couldn't find it in current dir
			fmt.Errorf("couldn't find config file")
			os.Exit(-1)
		}
	}

	var config interface{}
	err = json.Unmarshal(dat, &config)
	if err != nil {
		fmt.Errorf("failed to parse config")
		os.Exit(-1)
	}

	return config.(map[string]interface{})
}

func configHasKey(key string) bool {
	// handles the case where the key doesn't exist and if the value is an empty string
	if val, ok := config[key]; ok && len(val.(string)) > 0 {
		return true
	}
	return false
}

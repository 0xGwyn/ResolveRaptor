package runner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func getCrtshSubs(domain, out string) error {
	gologger.Debug().Msg("gathering subdomains from Crt.sh")

	type crtshSubs struct {
		Common_name string `json:"common_name"`
		Name_value  string `json:"name_value"`
	}

	var jsonOutput []crtshSubs

	req, err := http.NewRequest("GET", "http://crt.sh/?q="+domain+"&output=json", nil)
	if err != nil {
		return err
	}
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0")

	// send get request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		gologger.Warning().Msg("get request to crt.sh failed")
		return err
	}
	defer resp.Body.Close()

	// check if the response code is not code 200
	if resp.StatusCode != 200 {
		gologger.Warning().Msg("crt.sh failed")
		return nil
	}

	// decode the json response
	err = json.NewDecoder(resp.Body).Decode(&jsonOutput)
	if err != nil {
		return err
	}

	// make regex pattern to remove wildcards
	reg := regexp.MustCompile(`\*.`)

	// read the subdomains into a map to make it unique
	uniqueLinesMap := make(map[string]bool)
	for _, value := range jsonOutput {
		// replace *. with empty string
		wildcardOmitted := reg.ReplaceAllString(value.Common_name, "")
		uniqueLinesMap[wildcardOmitted] = true

		// replace *. with empty string then split multiple subdomains
		wildcardOmitted = reg.ReplaceAllString(value.Name_value, "")
		splitted := strings.Split(wildcardOmitted, "\n")

		for _, sub := range splitted {
			uniqueLinesMap[sub] = true
		}
	}

	// create output file
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// write unique subdomains to output
	for sub := range uniqueLinesMap {
		fmt.Fprintln(file, sub)
	}

	// display number of subdomains found
	gologger.Debug().Msg("Crt.sh: " + strconv.Itoa(len(uniqueLinesMap)) + " subdomains were found")

	return nil
}

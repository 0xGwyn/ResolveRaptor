package runner

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func getAbuseipdbSubs(domain, out string) error {
	gologger.Debug().Msg("gathering subdomains from AbuseIPDB")

	req, err := http.NewRequest("GET", "https://www.abuseipdb.com/whois/"+domain, nil)
	if err != nil {
		return err
	}
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0")

	// send get request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		gologger.Warning().Msg("get request to abuseipdb failed")
		return err
	}
	defer resp.Body.Close()

	// check if the response code is not code 200
	if resp.StatusCode != 200 {
		gologger.Warning().Msg("abuseipdb failed")
		return nil
	}

	// convert the response to bytes
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// grep matches
	reg, err := regexp.Compile(`<li>\w.*</li>`)
	if err != nil {
		return err
	}
	submatches := reg.FindAllString(string(content), -1)

	// create output file
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// write trimmed matches to output file
	for _, submatch := range submatches {
		submatch = strings.TrimPrefix(submatch, "<li>")
		submatch = strings.TrimSuffix(submatch, "</li>")
		subdomain := submatch + "." + domain
		file.WriteString(subdomain + "\n")
	}

	// display number of subdomains found
	gologger.Debug().Msg("AbuseIPDB: " + strconv.Itoa(len(submatches)) + " subdomains were found")

	return nil
}

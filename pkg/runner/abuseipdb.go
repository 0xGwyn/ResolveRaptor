package runner

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

func getAbuseipdbSubs(domain, out, sessionCookie string) error {
	gologger.Debug().Msg("gathering subdomains from AbuseIPDB")

	// create output file
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	req, err := http.NewRequest("GET", "https://www.abuseipdb.com/whois/"+domain, nil)
	if err != nil {
		return err
	}
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0")

	// create a new session cookie
	cookie := &http.Cookie{
		Name:  "abuseipdb_session",
		Value: sessionCookie,
	}

	// add the session cookie to the request
	req.AddCookie(cookie)

	// send get request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
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

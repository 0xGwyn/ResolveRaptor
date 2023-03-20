package runner

import (
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func runShuffledns(domain, resolver, in, out string) error {
	gologger.Debug().Msg("running Shuffledns on " + path.Base(in))

	cmd := exec.Command("shuffledns", "-silent", "-d", domain, "-r", resolver, "-l", in)
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// create a file then write the shuffledns output to it
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	file.Write(output)

	// display number of resolved subdomains
	resolved := strings.Split(string(output), "\n")
	gologger.Debug().Msg("Shuffledns: " + strconv.Itoa(len(resolved)) + " subdomains were resolved")

	return nil
}

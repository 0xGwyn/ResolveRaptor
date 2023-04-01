package runner

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func getChaosSubs(domain, out string) error {
	gologger.Debug().Msg("gathering subdomains using Chaos on " + domain)

	// create a file then write the chaos output to it
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	cmd := exec.Command("chaos", "-d", domain, "-silent")
	output, err := cmd.Output()
	if err != nil {
		gologger.Warning().Msg("chaos failed to get subdomains(check if CHAOS_KEY env variable exists)")
		return nil
	}

	// remove wildcard symbol "*."
	outputStr := strings.ReplaceAll(string(output), "*.", "")

	// write chaos results to output
	file.WriteString(outputStr)

	// display number of subdomains found
	subs := strings.Split(string(output), "\n")
	gologger.Debug().Msg("Chaos: " + strconv.Itoa(len(subs)) + " subdomains were found")

	return nil
}

package runner

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func runSubfinder(domain, out string, allFlag bool) error {
	debug("gathering subdomains using Subfinder on " + domain)

	var cmd *exec.Cmd
	if allFlag {
		cmd = exec.Command("subfinder", "-d", domain, "-silent", "-all")
	} else {
		cmd = exec.Command("subfinder", "-d", domain, "-silent")
	}
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// create a file then write the subfinder output to it
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	file.Write(output)

	// display number of subdomains found
	subs := strings.Split(string(output), "\n")
	debug("Subfinder: " + strconv.Itoa(len(subs)) + " subdomains were found")

	return nil
}

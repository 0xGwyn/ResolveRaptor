package runner

import (
	"os"
	"os/exec"
	"path"

	"github.com/projectdiscovery/gologger"
)

func runDnsgen(in, out string, fastFlag bool) error {
	gologger.Debug().Msg("running Dnsgen on " + path.Base(in))

	//read the input file
	inputFile, err := os.Open(in)
	if err != nil {
		return err
	}

	//provide dnsgen with the output from the cat command
	var cmd *exec.Cmd
	if fastFlag {
		cmd = exec.Command("dnsgen", "-", "-f")
	} else {
		cmd = exec.Command("dnsgen", "-")
	}
	cmd.Stdin = inputFile
	dnsgenOutput, err := cmd.Output()
	if err != nil {
		return err
	}

	//create a file then write the dnsgen output to it
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	file.Write(dnsgenOutput)

	return nil
}

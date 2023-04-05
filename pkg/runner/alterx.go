package runner

import (
	"os"
	"os/exec"
	"path"

	"github.com/projectdiscovery/gologger"
)

func runAlterx(in, out string, enrich bool) error {
	gologger.Debug().Msg("running Alterx on " + path.Base(in))

	//read the input file
	inputFile, err := os.Open(in)
	if err != nil {
		return err
	}

	//provide alterx with input
	var cmd *exec.Cmd
	if enrich {
		cmd = exec.Command("alterx", "-silent", "-enrich")
	} else {
		cmd = exec.Command("alterx", "-silent")
	}
	cmd.Stdin = inputFile
	alterxOutput, err := cmd.Output()
	if err != nil {
		return err
	}

	//create a file then write the alterx output to it
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	file.Write(alterxOutput)

	return nil
}

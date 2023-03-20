package main

import (
	"github.com/0xgwyn/resolveraptor/pkg/runner"
	"github.com/projectdiscovery/gologger"
)

func main() {
	options := runner.ParseOptions()

	runner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	err = runner.Start()
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

}

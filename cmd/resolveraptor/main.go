package main

import (
	"github.com/0xgwyn/resolveraptor/pkg/runner"
)

func main() {
	options := runner.ParseOptions()

	runner, err := runner.NewRunner(options)
	if err != nil {
		panic(err)
	}

	err = runner.Start()
	if err != nil {
		panic(err)
	}

}

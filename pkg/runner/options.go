package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type Options struct {
	domain          string
	wordlist        string
	resolver        string
	fast            bool
	cleanup         bool
	verbose         bool
	all             bool
	silent          bool
	enrich          bool
	output          string
	permutationTool string
}

func ParseOptions() *Options {
	options := &Options{}

	flags := goflags.NewFlagSet()
	flags.SetDescription("ResolveRaptor is a wrapper for DNS bruteforcing tools that implements a custom bruteforcing flow to find/resolve as much subdomains as possible")

	flags.CreateGroup("input", "Input",
		flags.StringVarP(&options.domain, "domain", "d", "", "Target domain name"),
		flags.StringVarP(&options.wordlist, "wordlist", "w", "", "DNS wordlist filename"),
		flags.StringVarP(&options.resolver, "resolver", "r", "", "Resolver filename"),
	)

	flags.CreateGroup("options", "Options",
		flags.BoolVarP(&options.fast, "fast", "f", false, "Fast flag for dnsgen"),
		flags.BoolVarP(&options.cleanup, "cleanup", "c", false, "Clean up all files except the final result"),
		flags.BoolVarP(&options.all, "all", "a", false, "All flag for subfinder"),
		flags.BoolVarP(&options.silent, "silent", "s", false, "Only show resolved subdomains"),
		flags.BoolVarP(&options.enrich, "enrich", "en", false, "Enrich flag for alterx"),
		flags.StringVarP(&options.permutationTool, "permutation-tool", "pt", "alterx", "Permutation tool (dnsgen or alterx)"),
	)

	flags.CreateGroup("output", "Output",
		flags.StringVarP(&options.output, "output", "o", "final", "Output filename"),
		flags.BoolVarP(&options.verbose, "verbose", "v", false, "Verbose output"),
	)

	if err := flags.Parse(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	options.configureOutput()

	if !options.silent {
		showBanner()
	}

	if err := options.validateOptions(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	return options
}

// checks if options are validated
func (options *Options) validateOptions() error {
	// checks if subfinder is installed
	if _, err := exec.LookPath("subfinder"); err != nil {
		return fmt.Errorf("subfinder is not found in the path")
	}

	// checks if shuffledns is installed
	if _, err := exec.LookPath("shuffledns"); err != nil {
		return fmt.Errorf("shuffledns is not found in the path")
	}

	if options.permutationTool == "dnsgen" {
		// checks if dnsgen is installed
		if _, err := exec.LookPath("dnsgen"); err != nil {
			return fmt.Errorf("dnsgen is not found in the path")
		}
	} else if options.permutationTool == "alterx" {
		// checks if alterx is installed
		if _, err := exec.LookPath("alterx"); err != nil {
			return fmt.Errorf("alterx is not found in the path")
		}
	} else {
		// if permutation tool is unknown
		return fmt.Errorf("the permutation tool given to the program is neither alterx nor dnsgen")
	}

	// checks if a domain is given
	if options.domain == "" {
		return errors.New("domain name was not provided")
	}

	// checks if wordlist is given or if it exists
	if options.wordlist == "" {
		return errors.New("no wordlist was provided")
	}
	if _, err := os.Stat(options.wordlist); os.IsNotExist(err) {
		return errors.New("wordlist file does not exist")
	}

	// checks if resolver file is given or if it exists
	if options.resolver == "" {
		return errors.New("no resolver file was provided")
	}
	if _, err := os.Stat(options.resolver); os.IsNotExist(err) {
		return errors.New("resolver file does not exist")
	}

	// checks if resolver file is empty
	if stat, err := os.Stat(options.resolver); err != nil {
		return errors.New("an error occurred while opening the resolver file")
	} else if stat.Size() <= 1 {
		return errors.New("resolver file is empty")
	}

	// checks if output file already exists
	if _, err := os.Stat(options.output); !os.IsNotExist(err) {
		return fmt.Errorf("a file under the name %v already exists", options.output)
	}

	// checks if both silent and verbose flags are used
	if options.verbose && options.silent {
		return errors.New("can't use both silent and verbose mode")
	}

	return nil
}

// configures the output on the screen
func (options *Options) configureOutput() {
	// if the user desires verbose output, show verbose output
	if options.verbose {
		gologger.DefaultLogger.SetTimestamp(true, levels.LevelDebug)
		gologger.DefaultLogger.SetTimestamp(true, levels.LevelWarning)
		gologger.DefaultLogger.SetTimestamp(true, levels.LevelFatal)
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

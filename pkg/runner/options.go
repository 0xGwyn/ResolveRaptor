package runner

import (
	"errors"
	"fmt"
	"os"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type Options struct {
	domain   string
	wordlist string
	resolver string
	fast     bool
	cleanup  bool
	verbose  bool
	all      bool
	silent   bool
	output   string
}

func ParseOptions() *Options {
	options := &Options{}

	flags := goflags.NewFlagSet()
	flags.SetDescription("ResolveRaptor is a wrapper around DNS bruteforcing tools that implements a custom bruteforcing flow to find/resolve as much subdomains as possible")

	flags.CreateGroup("input", "Input",
		flags.StringVarP(&options.domain, "domain", "d", "", "Target domain name"),
		flags.StringVarP(&options.wordlist, "wordlist", "w", "", "DNS wordlist filename"),
		flags.StringVarP(&options.resolver, "resolver", "r", "", "Resolver filename"),
	)

	flags.CreateGroup("options", "Options",
		flags.BoolVarP(&options.fast, "fast", "f", false, "Fast switch for Dnsgen (default: false)"),
		flags.BoolVarP(&options.cleanup, "cleanup", "c", false, "Unessential files cleanup"),
		flags.BoolVarP(&options.all, "all", "a", false, "All flag for subfinder"),
		flags.BoolVarP(&options.silent, "silent", "s", false, "Show only resolved subdomains"),
	)

	flags.CreateGroup("output", "Output",
		flags.StringVarP(&options.output, "output", "o", "final", "Output filename"),
		flags.BoolVarP(&options.verbose, "verbose", "v", false, "Verbose output (default: false)"),
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

// check if options are validated
func (options *Options) validateOptions() error {
	//Check if a domain is given
	if options.domain == "" {
		return errors.New("domain name was not provided")
	}

	//Check if wordlist is given or if it exists
	if options.wordlist == "" {
		return errors.New("no wordlist was provided")
	}
	if _, err := os.Stat(options.wordlist); os.IsNotExist(err) {
		return errors.New("wordlist file does not exist")
	}

	//Check if resolver file is given or if it exists
	if options.resolver == "" {
		return errors.New("no resolver file was provided")
	}
	if _, err := os.Stat(options.resolver); os.IsNotExist(err) {
		return errors.New("resolver file does not exist")
	}

	//Check if resolver file is empty
	if stat, err := os.Stat(options.resolver); err != nil {
		return errors.New("an error occurred while opening the resolver file")
	} else if stat.Size() <= 1 {
		return errors.New("resolver file is empty")
	}

	//Check if output file already exists
	if _, err := os.Stat(options.output); !os.IsNotExist(err) {
		return fmt.Errorf("a file under the name %v already exists", options.output)
	}

	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
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

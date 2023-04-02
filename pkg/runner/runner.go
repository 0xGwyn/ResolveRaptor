package runner

import (
	"path"
	"sync"

	"github.com/projectdiscovery/gologger"
)

type Runner struct {
	options *Options
}

func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}

	return runner, nil
}

func (runner *Runner) Start() error {
	gologger.Info().Msg("DNS Brute-forcing for " + runner.options.domain)

	//create a directory for the specified target domain
	err := makeDir(runner.options.domain)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(4)

	//generate subdomains based on the given wordlist
	go func() {
		defer wg.Done()
		err = makeSubsFromWordlist(
			runner.options.domain,
			runner.options.wordlist,
			path.Join(runner.options.domain, "generated.subs"),
		)
		if err != nil {
			gologger.Fatal().Msg("Error while making subdomains from wordlist: " + err.Error())
		}
	}()

	//run subfinder on the specified target domain
	go func() {
		defer wg.Done()
		err = runSubfinder(
			runner.options.domain,
			path.Join(runner.options.domain, "subfinder.subs"),
			runner.options.all,
		)
		if err != nil {
			gologger.Fatal().Msg("Error while running subfinder: " + err.Error())
		}
	}()

	//get abuseipdb subs for the specified target domain
	go func() {
		defer wg.Done()
		err = getAbuseipdbSubs(
			runner.options.domain,
			path.Join(runner.options.domain, "abuseipdb.subs"),
		)
		if err != nil {
			gologger.Fatal().Msg("Error while getting subdomains from Abuseipdb: " + err.Error())
		}
	}()

	//get crtsh subs for the specified target domain
	go func() {
		defer wg.Done()
		err = getCrtshSubs(
			runner.options.domain,
			path.Join(runner.options.domain, "crtsh.subs"),
		)
		if err != nil {
			gologger.Fatal().Msg("Error while getting subdomains from Crt.sh: " + err.Error())
		}
	}()

	//waiting for subfinder, crtsh and abusedpip results
	wg.Wait()

	//merge generated subdomains with subfinder output then sort and uniquify them
	err = mergeFiles(
		path.Join(runner.options.domain, "generated.subs"),
		path.Join(runner.options.domain, "subfinder.subs"),
		path.Join(runner.options.domain, "shuffledns_phase1.in"),
	)
	if err != nil {
		return err
	}

	//merge crt.sh subdomains with abuseipdb subdomains then sort and uniquify them
	err = mergeFiles(
		path.Join(runner.options.domain, "crtsh.subs"),
		path.Join(runner.options.domain, "abuseipdb.subs"),
		path.Join(runner.options.domain, "shuffledns_phase1.in"),
	)
	if err != nil {
		return err
	}

	//run shuffledns
	err = runShuffledns(runner.options.domain, runner.options.resolver,
		path.Join(runner.options.domain, "shuffledns_phase1.in"),
		path.Join(runner.options.domain, "shuffledns_phase1.out"),
	)
	if err != nil {
		return err
	}

	//merge the resolved subdomains and the subfinder output for permulation tools
	err = mergeFiles(
		path.Join(runner.options.domain, "shuffledns_phase1.out"),
		path.Join(runner.options.domain, "subfinder.subs"),
		path.Join(runner.options.domain, "permutation.in"),
	)
	if err != nil {
		return err
	}

	//run dnsgen on the resolved subdomains and the subfinder output merged file
	err = runDnsgen(
		path.Join(runner.options.domain, "permutation.in"),
		path.Join(runner.options.domain, "shuffledns_phase2.in"),
		runner.options.fast,
	)
	if err != nil {
		return err
	}

	//merge permutation.in with shuffledns_phase2.in since dnsgen output does not contain all inputs
	err = mergeFiles(
		path.Join(runner.options.domain, "shuffledns_phase2.in"),
		path.Join(runner.options.domain, "permutation.in"),
		path.Join(runner.options.domain, "shuffledns_phase2.in"),
	)
	if err != nil {
		return err
	}

	//run shuffledns
	err = runShuffledns(
		runner.options.domain,
		runner.options.resolver,
		path.Join(runner.options.domain, "shuffledns_phase2.in"),
		path.Join(runner.options.domain, "shuffledns_phase2.out"),
	)
	if err != nil {
		return err
	}

	//merge shuffledns_phase1.out with shuffledns_phase2.out
	err = mergeFiles(
		path.Join(runner.options.domain, "shuffledns_phase1.out"),
		path.Join(runner.options.domain, "shuffledns_phase2.out"),
		path.Join(runner.options.domain, runner.options.output),
	)
	if err != nil {
		return err
	}

	//print results to stdout
	printResults(
		runner.options.silent,
		path.Join(runner.options.domain, runner.options.output),
	)

	//cleanup only if the flag is set
	if runner.options.cleanup {
		err := cleanup(runner.options.domain)
		if err != nil {
			return err
		}
	}

	return nil
}

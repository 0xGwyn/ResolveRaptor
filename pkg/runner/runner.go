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
	wg.Add(3)

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
			runner.options.abuseipdbSession,
		)
		if err != nil {
			gologger.Fatal().Msg("Error while getting subdomains from Abuseipdb: " + err.Error())
		}
	}()

	//waiting for go routines
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

	//merge abusedbip subdomains with shuffledns_phase1.in then sort and uniquify them
	err = mergeFiles(
		path.Join(runner.options.domain, "abuseipdb.subs"),
		path.Join(runner.options.domain, "shuffledns_phase1.in"),
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

	// check if unresolved subdomains found in phase1 should be added for permutation
	if runner.options.includeUnresolvedSubs {
		//merge the resolved subdomains and the subfinder output for permulation tools
		err = mergeFiles(
			path.Join(runner.options.domain, "shuffledns_phase1.out"),
			path.Join(runner.options.domain, "subfinder.subs"),
			path.Join(runner.options.domain, "permutation.in"),
		)
		if err != nil {
			return err
		}

		//merge the resolved subdomains and the abuseipdb output for permulation tools
		err = mergeFiles(
			path.Join(runner.options.domain, "abuseipdb.subs"),
			path.Join(runner.options.domain, "permutation.in"),
			path.Join(runner.options.domain, "permutation.in"),
		)
		if err != nil {
			return err
		}
	} else {
		// rename shuffledns_phase1.out to permutation.in
		err = renameFile(
			path.Join(runner.options.domain, "shuffledns_phase1.out"),
			path.Join(runner.options.domain, "permutation.in"),
		)
	}

	// either run dnsgen or alterx
	if runner.options.permutationTool == "alterx" {
		//run alterx on the resolved subdomains and the subfinder output merged file
		err = runAlterx(
			path.Join(runner.options.domain, "permutation.in"),
			path.Join(runner.options.domain, "shuffledns_phase2.in"),
			runner.options.enrich,
		)
	} else if runner.options.permutationTool == "dnsgen" {
		//run dnsgen on the resolved subdomains and the subfinder output merged file
		err = runDnsgen(
			path.Join(runner.options.domain, "permutation.in"),
			path.Join(runner.options.domain, "shuffledns_phase2.in"),
			runner.options.fast,
		)
	}
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
	//(if include_unresolved_subs is false then use permutation.in instead of shuffledns_phase1.out)
	if runner.options.includeUnresolvedSubs {
		err = mergeFiles(
			path.Join(runner.options.domain, "shuffledns_phase1.out"),
			path.Join(runner.options.domain, "shuffledns_phase2.out"),
			path.Join(runner.options.domain, runner.options.output),
		)
	} else {
		err = mergeFiles(
			path.Join(runner.options.domain, "permutation.in"),
			path.Join(runner.options.domain, "shuffledns_phase2.out"),
			path.Join(runner.options.domain, runner.options.output),
		)
	}
	if err != nil {
		return err
	}

	//print results to stdout
	printResults(path.Join(runner.options.domain, runner.options.output))

	//cleanup only if the flag is set
	if runner.options.cleanup {
		err := cleanup(runner.options.domain)
		if err != nil {
			return err
		}
	}

	return nil
}

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
)

type Options struct {
	domain   string
	wordlist string
	resolver string
	fast     bool
	cleanup  bool
	verbose  bool
	// silent   bool
	output string
}

var options *Options

func main() {
	options = parseOptions()
	debug("running the program")
	makeSubsFromWordlist(options.wordlist, "subdomains")
	sortAndUniquify("test")
}

func mergeFiles(file1, file2, output string) error {
	//open output file or create if does not exist
	destination, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		// The file already exists
		return fmt.Errorf("the %v file already exists", output)
	}
	defer destination.Close()

	f1, err := os.Open(file1)
	if err != nil {
		return err
	}
	defer f1.Close()

	f2, err := os.Open(file2)
	if err != nil {
		return err
	}
	defer f2.Close()

	io.Copy(destination, f1)
	io.Copy(destination, f2)

	/*f1Scanner := bufio.NewScanner(f1)
	if f1Scanner.Scan() {
		fmt.Fprintln(destination, f1Scanner.Text())
	}

	f2Scanner := bufio.NewScanner(f2)
	if f2Scanner.Scan() {
		fmt.Fprintln(destination, f2Scanner.Text())
	}*/

	return nil
}

func sortAndUniquify(file string) error {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	// get file content as a string slice
	lines := strings.Split(string(content), "\n")
	// sort and uniquify the file
	sort.Strings(lines)
	uniqueLines := make([]string, 0, len(lines))
	seen := make(map[string]bool)
	for _, line := range lines {
		if !seen[line] {
			seen[line] = true
			uniqueLines = append(uniqueLines, line)
		}
	}

	f, err := os.OpenFile(file, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	for _, line := range uniqueLines {
		fmt.Fprintln(f, line)
	}
	defer f.Close()

	return nil
}

func makeSubsFromWordlist(wordlistFilename, subdomainsFilename string) error {
	//open the wordlist file
	wordlist, err := os.Open(wordlistFilename)
	if err != nil {
		return err
	}
	defer wordlist.Close()

	//open a file for subdomains
	subdomains, err := os.OpenFile(subdomainsFilename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		// The file already exists
		return fmt.Errorf("the %v file for subdomains already exists", subdomainsFilename)
	}
	defer subdomains.Close()

	scanner := bufio.NewScanner(wordlist)
	for scanner.Scan() {
		subdomain := fmt.Sprintf("%v.%v", scanner.Text(), options.domain)
		fmt.Fprintln(subdomains, subdomain)
	}

	return nil
}

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

func parseOptions() *Options {
	options := &Options{}

	flags := goflags.NewFlagSet()
	flags.SetDescription("ResolveRaptor's a wrapper around DNS bruteforcing tools that implements a custom bruteforcing flow to find as much subdomains as possible")

	flags.CreateGroup("input", "Input",
		flags.StringVarP(&options.domain, "domain", "d", "", "Target domain name"),
		flags.StringVarP(&options.wordlist, "wordlist", "w", "", "DNS wordlist filename"),
		flags.StringVarP(&options.resolver, "resolver", "r", "", "Resolver filename"),
	)

	flags.CreateGroup("options", "Options",
		flags.BoolVarP(&options.fast, "fast", "f", false, "Fast switch for Dnsgen (default: false)"),
		flags.BoolVarP(&options.cleanup, "cleanup", "c", false, "Unessential files cleanup"),
	)

	flags.CreateGroup("output", "Output",
		flags.StringVarP(&options.output, "output", "o", "final", "Output filename"),
		flags.BoolVarP(&options.verbose, "verbose", "v", false, "Verbose output (default: false)"),
	)

	if err := flags.Parse(); err != nil {
		panic(err)
	}

	if err := options.validateOptions(); err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}

	return options
}

func debug(msg string) {
	if options.verbose {
		time := getCurrentTime()
		fmt.Printf("[%v] Debug: %v\n", time, msg)
	}
}

func getCurrentTime() string {
	currentTime := time.Now()
	formattedTime := currentTime.Format("17:06:06")

	return formattedTime
}

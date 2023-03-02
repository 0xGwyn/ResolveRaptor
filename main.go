package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	all      bool
	silent   bool
	output   string
}

var options *Options

func main() {
	//parse flags
	options = parseOptions()

	//print banner
	printBanner()

	//create a directory for the specified target domain
	err := makeDir(options.domain)
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	wg.Add(4)

	//generate subdomains based on the given wordlist
	go func() {
		defer wg.Done()
		err = makeSubsFromWordlist(options.wordlist, path.Join(options.domain, "generated.subs"))
		if err != nil {
			panic(err)
		}
	}()

	//run subfinder on the specified target domain
	go func() {
		defer wg.Done()
		err = runSubfinder(path.Join(options.domain, "subfinder.subs"))
		if err != nil {
			panic(err)
		}
	}()

	//get abuseipdb subs for the specified target domain
	go func() {
		defer wg.Done()
		err = getAbuseipdbSubs(path.Join(options.domain, "abuseipdb.subs"))
		if err != nil {
			panic(err)
		}
	}()

	//get crtsh subs for the specified target domain
	go func() {
		defer wg.Done()
		err = getCrtshSubs(path.Join(options.domain, "crtsh.subs"))
		if err != nil {
			panic(err)
		}
	}()

	// waiting for subfinder, crtsh and abusedpip results
	wg.Wait()

	//merge generated subdomains with subfinder output then sort and uniquify them
	err = mergeFiles(path.Join(options.domain, "generated.subs"), path.Join(options.domain, "subfinder.subs"), path.Join(options.domain, "shuffledns_phase1.in"))
	if err != nil {
		panic(err)
	}

	//merge crt.sh subdomains with abuseipdb subdomains then sort and uniquify them
	err = mergeFiles(path.Join(options.domain, "crtsh.subs"), path.Join(options.domain, "abuseipdb.subs"), path.Join(options.domain, "shuffledns_phase1.in"))
	if err != nil {
		panic(err)
	}

	//run shuffledns
	err = runShuffledns(path.Join(options.domain, "shuffledns_phase1.in"), path.Join(options.domain, "shuffledns_phase1.out"))
	if err != nil {
		panic(err)
	}

	//merge the resolved subdomains and the subfinder output for permulation tools
	err = mergeFiles(path.Join(options.domain, "shuffledns_phase1.out"), path.Join(options.domain, "subfinder.subs"), path.Join(options.domain, "permutation.in"))
	if err != nil {
		panic(err)
	}

	//run dnsgen on the resolved subdomains and the subfinder output merged file
	err = runDnsgen(path.Join(options.domain, "permutation.in"), path.Join(options.domain, "shuffledns_phase2.in"))
	if err != nil {
		panic(err)
	}

	//run shuffledns
	err = runShuffledns(path.Join(options.domain, "shuffledns_phase2.in"), path.Join(options.domain, "shuffledns_phase2.out"))
	if err != nil {
		panic(err)
	}

	//merge shuffledns_phase1.out with shuffledns_phase2.out
	err = mergeFiles(path.Join(options.domain, "shuffledns_phase1.out"), path.Join(options.domain, "shuffledns_phase2.out"), path.Join(options.domain, options.output))
	if err != nil {
		panic(err)
	}

	//print results to stdout
	printResults(path.Join(options.domain, options.output))

	//cleanup only if the flag is set
	if options.cleanup {
		err := cleanup()
		if err != nil {
			panic(err)
		}
	}

}

func printBanner() {

	banner := `
____                  _           ____             _             
|  _ \ ___  ___  ___ | |_   _____|  _ \ __ _ _ __ | |_ ___  _ __ 
| |_) / _ \/ __|/ _ \| \ \ / / _ \ |_) / _' | '_ \| __/ _ \| '__|
|  _ <  __/\__ \ (_) | |\ V /  __/  _ < (_| | |_) | || (_) | |   
|_| \_\___||___/\___/|_| \_/ \___|_| \_\__,_| .__/ \__\___/|_|  
					    |_|                  

	`
	if !options.silent {
		fmt.Fprintln(os.Stdout, banner)
	}
}

func printResults(file string) error {
	debug("printing final results")

	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	numOfLines := 0
	for scanner.Scan() {
		fmt.Fprintln(os.Stdout, scanner.Text())
		numOfLines++
	}

	if !options.silent {
		fmt.Printf("%v subdomains were resolved\n", numOfLines)
	}

	return nil
}

func getCrtshSubs(out string) error {
	debug("gathering subdomains from Crt.sh")

	type crtshSubs struct {
		Common_name string `json:"common_name"`
		Name_value  string `json:"name_value"`
	}

	var jsonOutput []crtshSubs

	req, err := http.NewRequest("GET", "http://crt.sh/?q="+options.domain+"&output=json", nil)
	if err != nil {
		return err
	}
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0")

	// send get request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// check if the response code is not code 200
	if resp.StatusCode != 200 {
		debug("crt.sh failed")
		os.Create(out)
		return nil
	}

	// decode the json response
	err = json.NewDecoder(resp.Body).Decode(&jsonOutput)
	if err != nil {
		return err
	}

	// make regex pattern to remove wildcards
	reg := regexp.MustCompile(`\*.`)

	// read the subdomains into a map to make it unique
	uniqueLinesMap := make(map[string]bool)
	for _, value := range jsonOutput {
		// replace *. with empty string
		wildcardOmitted := reg.ReplaceAllString(value.Common_name, "")
		uniqueLinesMap[wildcardOmitted] = true

		// replace *. with empty string then split multiple subdomains
		wildcardOmitted = reg.ReplaceAllString(value.Name_value, "")
		splitted := strings.Split(wildcardOmitted, "\n")

		for _, sub := range splitted {
			uniqueLinesMap[sub] = true
		}
	}

	// create output file
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// write unique subdomains to output
	for sub := range uniqueLinesMap {
		fmt.Fprintln(file, sub)
	}

	// display number of subdomains found
	debug("Crt.sh: " + strconv.Itoa(len(uniqueLinesMap)) + " subdomains were found")

	return nil
}

func getAbuseipdbSubs(out string) error {
	debug("gathering subdomains from AbuseIPDB")

	req, err := http.NewRequest("GET", "https://www.abuseipdb.com/whois/"+options.domain, nil)
	if err != nil {
		return err
	}
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0")

	// send get request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// check if the response code is not code 200
	if resp.StatusCode != 200 {
		debug("abuseipdb failed")
		return nil
	}

	// convert the response to bytes
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// grep matches
	reg, err := regexp.Compile(`<li>\w.*</li>`)
	if err != nil {
		return err
	}
	submatches := reg.FindAllString(string(content), -1)

	// create output file
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// write trimmed matches to output file
	for _, submatch := range submatches {
		submatch = strings.TrimPrefix(submatch, "<li>")
		submatch = strings.TrimSuffix(submatch, "</li>")
		subdomain := submatch + "." + options.domain
		file.WriteString(subdomain + "\n")
	}

	// display number of subdomains found
	debug("AbuseIPDB: " + strconv.Itoa(len(submatches)) + " subdomains were found")

	return nil
}

func cleanup() error {
	debug("cleaning up unnecessary files")

	files := []string{
		"crtsh.subs", "abuseipdb.subs", "subfinder.subs", "generated.subs", "shuffledns_phase1.in",
		"shuffledns_phase1.out", "shuffledns_phase2.in", "shuffledns_phase2.out", "permutation.in",
	}

	for _, file := range files {
		err := os.Remove(path.Join(options.domain, file))
		if err != nil {
			return err
		}
	}

	return nil
}

func runDnsgen(in, out string) error {
	debug("Running Dnsgen on " + path.Base(in))

	//run cat on input
	cat := exec.Command("cat", in)
	catOutput, err := cat.Output()
	if err != nil {
		return err
	}

	//provide dnsgen with the output from the cat command
	var cmd *exec.Cmd
	if options.fast {
		cmd = exec.Command("dnsgen", "-", "-f")
	} else {
		cmd = exec.Command("dnsgen", "-")
	}
	cmd.Stdin = bytes.NewReader(catOutput)
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

func runShuffledns(in, out string) error {
	debug("running Shuffledns on " + path.Base(in))

	cmd := exec.Command("shuffledns", "-silent", "-d", options.domain, "-r", options.resolver, "-l", in)
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// create a file then write the shuffledns output to it
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	file.Write(output)

	// display number of resolved subdomains
	resolved := strings.Split(string(output), "\n")
	debug("Shuffledns: " + strconv.Itoa(len(resolved)) + " subdomains were resolved")

	return nil
}

func runSubfinder(out string) error {
	debug("gathering subdomains using Subfinder on " + options.domain)

	var cmd *exec.Cmd
	if options.all {
		cmd = exec.Command("subfinder", "-d", options.domain, "-silent", "-all")
	} else {
		cmd = exec.Command("subfinder", "-d", options.domain, "-silent")
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

func makeDir(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		debug("creating " + options.domain + " directory")
		err = os.Mkdir(dirPath, 0777)
		if err != nil {
			return err
		}
		return nil
	}
	debug("skipping " + options.domain + " directory creation since it already exists")

	return nil
}

func mergeFiles(file1, file2, output string) error {
	debug("merging " + path.Base(file1) + " with " + path.Base(file2) + " and saving as " + path.Base(output))

	// open file 1
	f1, err := os.Open(file1)
	if err != nil {
		return err
	}
	defer f1.Close()

	// open file 2
	f2, err := os.Open(file2)
	if err != nil {
		return err
	}
	defer f2.Close()

	// create tmp file to merge file 1 and file 2 contents in case the output is one of the previous files (avoiding loop)
	temp, err := os.CreateTemp("", "goMerge_")
	if err != nil {
		return err
	}
	defer temp.Close()
	defer os.Remove(temp.Name())

	// merge file 1 and file 2 into temp
	io.Copy(temp, f1)
	io.Copy(temp, f2)

	// check if output is one of the inputs
	var destination *os.File
	if file1 == output || file2 == output {
		destination, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer destination.Close()
	} else {
		destination, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			// The file already exists
			return fmt.Errorf("the %v file already exists", path.Base(output))
		}
		defer destination.Close()
	}

	// reset offset then copy temp to destination
	temp.Seek(0, 0)
	io.Copy(destination, temp)

	//sort then make unique
	err = sortAndUniquify(output)
	if err != nil {
		return err
	}

	return nil
}

func sortAndUniquify(file string) error {
	debug("sorting and uniquifying " + path.Base(file))

	// open the file
	fIn, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer fIn.Close()

	scanner := bufio.NewScanner(fIn)

	// read the whole file into a map
	uniqueLinesMap := make(map[string]bool)
	for scanner.Scan() {
		uniqueLinesMap[strings.TrimSpace(scanner.Text())] = true
	}

	// remove the blank line if it exists
	delete(uniqueLinesMap, "")

	var uniqueLinesSlice []string
	for key := range uniqueLinesMap {
		uniqueLinesSlice = append(uniqueLinesSlice, key)
	}

	// sort the file contents
	sort.Strings(uniqueLinesSlice)

	// open the same file to change its contents
	fOut, err := os.OpenFile(file, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer fOut.Close()

	for _, line := range uniqueLinesSlice {
		fmt.Fprintln(fOut, line)
	}

	return nil
}

func makeSubsFromWordlist(wordlistFilename, generatedFilename string) error {
	debug("generating subdomain list based on the " + path.Base(wordlistFilename) + " wordlist file")

	//open the wordlist file
	wordlist, err := os.Open(wordlistFilename)
	if err != nil {
		return err
	}
	defer wordlist.Close()

	//open a file for subdomains
	subdomains, err := os.OpenFile(generatedFilename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		// The file already exists
		return fmt.Errorf("the %v file for generated subdomains already exists", path.Base(generatedFilename))
	}
	defer subdomains.Close()

	numOfLines := 0
	scanner := bufio.NewScanner(wordlist)
	for scanner.Scan() {
		subdomain := fmt.Sprintf("%v.%v", scanner.Text(), options.domain)
		fmt.Fprintln(subdomains, subdomain)
		numOfLines++
	}

	// display number of subdomains generated
	debug("Generated: " + strconv.Itoa(numOfLines) + " subdomains were generated")

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
		fmt.Printf("[%v]\tDebug: %v\n", time, msg)
	}
}

func getCurrentTime() string {
	currentTime := time.Now()
	// formattedTime := currentTime.Format("17:06:06")
	formattedTime := fmt.Sprintf("%v:%v:%v", currentTime.Hour(), currentTime.Minute(), currentTime.Second())

	return formattedTime
}

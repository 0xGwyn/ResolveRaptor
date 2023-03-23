package runner

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func sortAndUniquify(file string) error {
	gologger.Debug().Msg("sorting and uniquifying " + path.Base(file))

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

// can handle if output is same as input
func mergeFiles(file1, file2, output string) error {
	gologger.Debug().Msg("merging " + path.Base(file1) + " with " + path.Base(file2) + " and saving as " + path.Base(output))

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
	// remove tmp file later
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

func makeDir(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		gologger.Debug().Msg("creating " + dirPath + " directory")
		err = os.Mkdir(dirPath, 0777)
		if err != nil {
			return err
		}
		return nil
	}
	gologger.Debug().Msg("skipping " + dirPath + " directory creation since it already exists")

	return nil
}

func cleanup(dir string) error {
	gologger.Debug().Msg("cleaning up unnecessary files")

	//list of files
	files := []string{
		"crtsh.subs", "abuseipdb.subs", "subfinder.subs", "generated.subs", "shuffledns_phase1.in",
		"shuffledns_phase1.out", "shuffledns_phase2.in", "shuffledns_phase2.out", "permutation.in",
	}

	for _, file := range files {
		err := os.Remove(path.Join(dir, file))
		if err != nil {
			return err
		}
	}

	return nil
}

func makeSubsFromWordlist(domain, wordlistFilename, generatedFilename string) error {
	gologger.Debug().Msg("generating subdomain list based on the " + path.Base(wordlistFilename) + " wordlist file")

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
		subdomain := fmt.Sprintf("%v.%v", scanner.Text(), domain)
		fmt.Fprintln(subdomains, subdomain)
		numOfLines++
	}

	// display number of subdomains generated
	gologger.Debug().Msg("Generated: " + strconv.Itoa(numOfLines) + " subdomains were generated")

	return nil
}

func printResults(silentFlag bool, file string) error {
	gologger.Debug().Msg("printing final results")

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

	gologger.Info().Msgf("%v subdomains were resolved\n", numOfLines)

	return nil
}

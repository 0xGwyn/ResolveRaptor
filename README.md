# ResolveRaptor
ResolveRaptor is a wrapper around DNS bruteforcing tools that implements a custom bruteforcing flow to find/resolve as much subdomains as possible.
It includes two phases.

## Installation
```bash
go install github.com/0xgwyn/resolveraptor/cmd/resolveraptor@latest
```
or
```bash
git clone https://github.com/0xGwyn/ResolveRaptor.git
cd ResolveRaptor
build -o $GOPATH/bin/resolveraptor cmd/resolveraptor/main.go
```

## Phase1
Subdomains generated based on a wordlist plus the subdomains gathered from providers are resolved and saved as `shuffledns_phase1.out`

## Phase2 
In phase2 resolved subdomains (plus the provider subdomains if the `-ius` flag is set) are given to tools like alterx or dnsgen to be 
permutated. The permutation results are then resolved and saved as `shuffledns_phase2.out`. Then `shuffledns_phase1.out` and `shuffledns_phase2.out` 
are merged in a file named `final` if no name is given for the output using `-o` flag.

# Flags
```yaml
INPUT:
   -d, -domain string    Target domain name
   -w, -wordlist string  DNS wordlist filename
   -r, -resolver string  Resolver filename

OPTIONS:
   -f, -fast                       Fast flag for dnsgen
   -c, -cleanup                    Clean up all files except the final result
   -a, -all                        All flag for subfinder
   -s, -silent                     Only show resolved subdomains
   -en, -enrich                    Enrich flag for alterx
   -pt, -permutation-tool string   Permutation tool (dnsgen or alterx) (default "alterx")
   -ius, -include-unresolved-subs  Include unresolved subdomains for permutation also
   -as, -abuseipdb-session string  Abuseipdb_session cookie (required for abuseipdb)

OUTPUT:
   -o, -output string  Output filename (default "final")
   -v, -verbose        Verbose output
```

# Simple Example 
```
resolveraptor -d domain_name -r path_to_resolvers -ius -w path_to_wordlist -en -pt alterx -v
```

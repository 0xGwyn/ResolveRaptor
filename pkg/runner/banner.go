package runner

import "github.com/projectdiscovery/gologger"

const banner = `
____                  _           ____             _             
|  _ \ ___  ___  ___ | |_   _____|  _ \ __ _ _ __ | |_ ___  _ __ 
| |_) / _ \/ __|/ _ \| \ \ / / _ \ |_) / _' | '_ \| __/ _ \| '__|
|  _ <  __/\__ \ (_) | |\ V /  __/  _ < (_| | |_) | || (_) | |   
|_| \_\___||___/\___/|_| \_/ \___|_| \_\__,_| .__/ \__\___/|_|  
					    |_|                  
`

func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
}

#BotSifter Go Client (Multi OS Support) 
##Build Instruction
To Build the Go Client for BotSifter you must have the Go Programming Language installed on your computer.  Visit the offical [Go Programming Site](https://golang.org/) to install your copy. 

###Libraries
The following dependancies are required to build the BotSifter Client. 
  1. github.com/cheggaaa/pb
  2. golang.org/x/oauth2
  3. golang.org/x/oauth2/google
  4. google.golang.org/api/analytics/v3
  5. gopkg.in/alecthomas/kingpin.v2
  6. gopkg.in/yaml.v2
  7. github.com/olekukonko/ts  (_Required for cross compiling the Windows version_)
  *Note instrustion on how to download and install libraries are on the Go Programming Site
  
### Build the Client
In your console enter the following to build the Go Client for BotSifter. "go build botsifter.go" (Without the quotes) This will build
a stand alone executable that will work on your system. 


### Optional Steps:

Building a OS specific executable with the following commands: "GOOS=linux go build botsifter.go" for linux builds, "GOOS=darwin go
build botsifter.go" for mac and "GOOS=windows go build botsifter.go" for windows. if you are getting error messages when trying to
build cross OS versions, this thread will help:
[http://stackoverflow.com/questions/27412601/cross-compiling-go](http://stackoverflow.com/questions/27412601/cross-compiling-go)

## BotSifter Command line Arguments

Enter "./botsifter -h" to see the help menu. (./botsifter  will be the main directory unless specified or you have moved the folder)

Flags:<br>
-h, --help        Show context-sensitive help (also try --help-long and --help-man).<br>
 --config=filename.txt  Specify custom config file<br>
 --confirm         Output confirmation of changes to screen without applying any changes (Bool)<br>
 --clean            Removes all BotSifter Filters from GA (Bool)<br>
 --download     Toggle downloading of BotSifter Filters from BotSifter (Bool)<br>
 

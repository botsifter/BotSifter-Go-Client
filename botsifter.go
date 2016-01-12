package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cheggaaa/pb"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/analytics/v3"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

type GoogleConfig struct {
	ClientID     string        `yaml:"ClientID"`
	ClientSecret string        `yaml:"ClientSecret"`
	RedirectURL  string        `yaml:"RedirectURL"`
	Port         string        `yaml:"Port"`
	UACode       string        `yaml:"UACode"`
	Person       Person        `yaml:"Credentials"`
	Token        *oauth2.Token `yaml:"Token"`
	View         string        `yaml:"View"`
	RefWhite     string        `yaml:"ReferrerWhiteList"`
	RefBlack     string        `yaml:"ReferrerBlackList"`
	UAWhite      string        `yaml:"UAWhiteList"`
	UABlack      string        `yaml:"UABlackList"`
	HostInc      string        `yaml:"HostnameInclude"`
}
type Person struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type PublicKey struct {
	ip_list       string
	referrer_list string
}

type IP struct {
	IP string `json:"Referrer"`
}

type Referrer struct {
	Referrer string
	Rank     string
	Score    string
}

func (r Referrer) length() int {
	return len(r.Referrer)
}
func (r Referrer) String() string {
	if len(r.Referrer) > 100 {
		r.Referrer = r.Referrer[0:100] + "..."
	}
	return fmt.Sprintf("\t%s\t%s\t%s", r.Rank, r.Referrer, r.Score)
}

type Referrers []Referrer

func (ref Referrers) Len() int {
	return len(ref)
}

func (ref Referrers) Swap(i, j int) {
	ref[i], ref[j] = ref[j], ref[i]
}

func (ref Referrers) Less(i, j int) bool {
	return ref[i].Referrer < ref[j].Referrer
}

func (in Referrers) indexOf(r Referrer) int {
	for i, ref := range in {
		if r.Referrer == ref.Referrer {
			return i
		}
	}

	return -1
}

func (leftSide Referrers) findEntriesOnlyInLeftSide(rightSide Referrers) Referrers {
	var tmpReferrers Referrers

	for _, ref := range leftSide {
		if rightSide.indexOf(ref) == -1 {
			tmpReferrers = append(tmpReferrers, ref)
		}
	}

	return tmpReferrers
}

func (leftSide Referrers) findInBoth(rightSide Referrers) Referrers {
	var tmpReferrers Referrers

	for _, ref := range leftSide {
		if rightSide.indexOf(ref) > -1 {
			tmpReferrers = append(tmpReferrers, ref)
		}
	}

	return tmpReferrers
}

type UserAgent struct {
	Referrer string
	Rank     string
	Score    string
}
type Status struct {
	Status string
}
type Response struct {
	IPList        []IP       `json:"IPs"`
	ReferrerList  []Referrer `json:"Referrers"`
	UserAgentList []Referrer `json:"UserAgents"`
	Status        string     `json:"Status"`
}

type Host struct {
	Hostname string
}

func (hos Hosts) Len() int {
	return len(hos)
}

func (hos Hosts) Swap(i, j int) {
	hos[i], hos[j] = hos[j], hos[i]
}

func (hos Hosts) Less(i, j int) bool {
	return hos[i].Hostname < hos[j].Hostname
}

type Hosts []Host

func (in Hosts) indexOf(h Host) int {
	for i, ref := range in {
		if h.Hostname == ref.Hostname {
			return i
		}
	}

	return -1
}

func (leftSide Hosts) findEntriesOnlyInLeftSide(rightSide Hosts) Hosts {
	var tmpHosts Hosts

	for _, ref := range leftSide {
		if rightSide.indexOf(ref) == -1 {
			tmpHosts = append(tmpHosts, ref)
		}
	}

	return tmpHosts
}

func (leftSide Hosts) findInBoth(rightSide Hosts) Hosts {
	var tmpHosts Hosts

	for _, ref := range leftSide {
		if rightSide.indexOf(ref) > -1 {
			tmpHosts = append(tmpHosts, ref)
		}
	}

	return tmpHosts
}

func (h Host) length() int {
	return len(h.Hostname)
}

func (h Host) String() string {
	return h.Hostname
}

type Config map[string]string

//Loads CSV into Struct with type Referrer
func ReadReferrerList(filename string) []Referrer {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = 3
	rawCSVdata, err := reader.ReadAll()

	if err != nil {
		fmt.Println(err)
	}
	refs := []Referrer{}
	for i := 1; i < len(rawCSVdata); i++ {
		ref := Referrer{rawCSVdata[i][0], rawCSVdata[i][1], rawCSVdata[i][2]}
		refs = append(refs, ref)
	}
	return refs
}

//Loads CSV into Struct with type Host
func ReadHostList(filename string) []Host {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = 1
	rawCSVdata, err := reader.ReadAll()

	if err != nil {
		fmt.Println(err)
	}
	hosts := []Host{}
	for i := 1; i < len(rawCSVdata); i++ {
		host := Host{rawCSVdata[i][0]}
		hosts = append(hosts, host)
	}

	return hosts
}

//Retrieves BotSifter list from server
func retreiveList(person Person) Response {
	//Download filter list

	filterAuth := `{"auth": {"userid": "` + person.Username + `","password": "` + person.Password + `"}}`
	// fmt.Println(filterAuth)
	filterEndpoint := "http://www.botsifter.com/api/getFilterList"
	auth := bytes.NewBuffer([]byte(filterAuth))
	r, _ := http.Post(filterEndpoint, "application/json", auth)
	response, _ := ioutil.ReadAll(r.Body)
	var resp Response
	json.Unmarshal(response, &resp)
	// log.Printf("%#v", resp)
	return resp
}

//User authorization with Google
func auth(conf *oauth2.Config, port string) *oauth2.Token {
	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
		// println("LINUX")
	case "windows", "darwin":
		err = exec.Command("open", url).Start()
		// println("MAC")
	default:
		err = fmt.Errorf("unsupported platform")
		// println("DEFAULT")
	}

	// Use the authorization code that is pushed to the redirect URL.
	// NewTransportWithCode will do the handshake to retrieve
	// an access token and initiate a Transport that is
	// authorized and authenticated by the retrieved token.

	c := make(chan string)

	http.HandleFunc("/finished", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		q := r.URL.Query()
		c <- q["code"][0]
	})

	go http.ListenAndServe(":"+port, nil)

	code := <-c
	fmt.Printf("Successfully received code")

	tok, err := conf.Exchange(oauth2.NoContext, code)

	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Valid user - Successfully exchanged code for token")
	}

	return tok
}

//Removes duplicate entries in struct
func RemoveDuplicates(xs *[]Referrer) {
	found := make(map[Referrer]bool)
	j := 0
	for i, x := range *xs {
		if !found[x] {
			found[x] = true
			(*xs)[j] = (*xs)[i]
			j++
		}
	}
	*xs = (*xs)[:j]
}

func RefMerge(List []Referrer, ShowBar bool) []string {
	count := 0
	filterList := []string{""}
	length := len(List)
	var bar *pb.ProgressBar
	if ShowBar == true {
		bar = pb.StartNew(length)
		bar.SetMaxWidth(80)
	}
	for _, Ref := range List {
		length = len(filterList[count])
		if length == 0 {
			filterList[count] = Ref.Referrer
		} else if length+Ref.length() <= 255 && length != 0 {
			filterList[count] += "|"
			filterList[count] += Ref.Referrer
		} else {
			count++
			filterList = append(filterList, Ref.Referrer)
			// filterList[count] = Ref.Referrer
		}
		if ShowBar == true {
			bar.Increment()
			time.Sleep(time.Millisecond * 50)
		}
	}
	if ShowBar == true {
		bar.Finish()
	}
	return filterList
}

func HostMerge(List []Host, ShowBar bool) []string {
	count := 0
	filterList := []string{""}
	length := len(List)
	var bar *pb.ProgressBar
	if ShowBar == true {
		bar = pb.StartNew(length)
		bar.SetMaxWidth(80)
	}
	for _, Host := range List {
		length = len(filterList[count])
		if length == 0 {
			filterList[count] = Host.Hostname
		} else if length+Host.length() <= 255 && length != 0 {
			filterList[count] += "|"
			filterList[count] += Host.Hostname
		} else {
			count++
			filterList = append(filterList, Host.Hostname)
			// filterList[count] = Ref.Referrer
		}
		if ShowBar == true {
			bar.Increment()
			time.Sleep(time.Millisecond * 50)
		}
	}
	if ShowBar == true {
		bar.Finish()
	}
	return filterList
}

var (
	configFile       = kingpin.Flag("config", "Specify custom config file").Default("config.txt").PlaceHolder("filename.txt").String()
	confirmFlag      = kingpin.Flag("confirm", "Output confirmation of changes to screen without applying any changes (Bool)").Default("false").Bool()
	cleanFlag        = kingpin.Flag("clean", "Removes all BotSifter Filters from GA (Bool)").Default("false").Bool()
	downloadListFlag = kingpin.Flag("download", "Toggle downloading of BotSifter Filters from BotSifter (Bool)").Default("true").Bool()
)

func main() {
	kingpin.CommandLine.HelpFlag.Short('h')

	kingpin.Parse()

	configFile := *configFile
	confirmFlag := *confirmFlag
	cleanFlag := *cleanFlag
	downloadListFlag := *downloadListFlag

	fmt.Println(configFile)

	w := new(tabwriter.Writer)
	var output io.Writer
	if confirmFlag == false {
		var err error
		// log.SetFlags(0)
		LogFileLocation := flag.String("log", "BotSifter.log", "Specifies path of the log file")
		output, err = os.OpenFile(*LogFileLocation, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Println(err)
			return
		}
	} else {
		log.SetFlags(0)
	}

	if output == nil {
		output = os.Stdout
	}
	w.Init(output, 4, 4, 2, ' ', 0)
	log.SetOutput(w)

	//Read config file
	var GooFig GoogleConfig
	data, err := ioutil.ReadFile(configFile)

	if err != nil {
		fmt.Println("Unable to open configuration file: " + configFile)
		return
	}
	//Load config data from file into struct
	err = yaml.Unmarshal(data, &GooFig)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("\nConfig File: \t\t[" + configFile + "]")
	fmt.Println("Include Refferers File: [" + GooFig.RefWhite + "]")
	fmt.Println("Exclude Refferers File: [" + GooFig.RefBlack + "]")
	fmt.Println("Include UA File: \t[" + GooFig.UAWhite + "]")
	fmt.Println("Exclude UA File: \t[" + GooFig.UABlack + "]")
	fmt.Println("Exclude Hostname File: \t[" + GooFig.HostInc + "]")

	//Loading variables from config struct
	WebPropertyId := GooFig.UACode
	AccountID := WebPropertyId[3:11]

	//Authentication settings
	conf := &oauth2.Config{
		ClientID:     GooFig.ClientID,
		ClientSecret: GooFig.ClientSecret,
		RedirectURL:  GooFig.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/analytics",
			"https://www.googleapis.com/auth/analytics.edit",
			"https://www.googleapis.com/auth/analytics.manage.users",
		},
		Endpoint: google.Endpoint,
	}

	//If the config data doesn't contain Auth Token we need to get one
	fmt.Println("")
	if GooFig.Token == nil {
		fmt.Print("Authenticating user...")
		GooFig.Token = auth(conf, GooFig.Port)
		fmt.Println("\t\t\t\t\tCompleted")
	}

	//Load new client and service to talk with Google api
	fmt.Print("Setting up Google client...")
	client := conf.Client(oauth2.NoContext, GooFig.Token)
	service, err := analytics.New(client)
	if err != nil {
		log.Fatalln(err)
		// GooFig.Token = nil
	}

	fmt.Println("\t\t\t\t\tCompleted")
	//Retrieve BotSifter list from server if the cleanFlag is false
	var resp Response
	var respDisplay Response
	//Load csv files into appropriate structs
	fmt.Print("Loading includes, excludes and hostname lists...")
	uainc := ReadReferrerList(GooFig.UAWhite)
	uaexc := ReadReferrerList(GooFig.UABlack)
	refs := ReadReferrerList(GooFig.RefWhite)
	excs := ReadReferrerList(GooFig.RefBlack)
	hosts := ReadHostList(GooFig.HostInc)

	fmt.Println("\t\tCompleted")

	if cleanFlag == false {
		if downloadListFlag == true {
			fmt.Print("Downloading BotSifter Referrer List...")
			resp = retreiveList(GooFig.Person)
			respDisplay = resp
			fmt.Println("\t\t\t\tCompleted")
		}

		if resp.Status == "Unauthorized" {
			fmt.Println("Download failed: Invalid username/password")
			return
		}

		//Append contents from includeList.csv onto the ReferrerList struct and remove duplicate entries
		fmt.Print("Merging local include data with BotSifter data...")
		resp.ReferrerList = append(resp.ReferrerList, refs...)
		resp.UserAgentList = append(resp.UserAgentList, uainc...)
		RemoveDuplicates(&resp.UserAgentList)
		RemoveDuplicates(&resp.ReferrerList)
		fmt.Println("\t\tCompleted")

		//Remove contents from ReferrerList which were found on the excludeList.csv
		fmt.Print("Removing local exclude data from BotSifter data...")
		resultsRef := []Referrer{}
		for _, compFilter := range resp.ReferrerList {
			found := false
			for _, exc := range excs {
				if compFilter.Referrer == exc.Referrer {
					found = true
				}
			}
			if !found {
				resultsRef = append(resultsRef, compFilter)
			}
		}
		resp.ReferrerList = resultsRef

		resultsUA := []Referrer{}
		for _, compFilter := range resp.UserAgentList {
			found := false
			for _, exc := range uaexc {
				if compFilter.Referrer == exc.Referrer {
					found = true
				}
			}
			if !found {
				resultsUA = append(resultsUA, compFilter)
			}
		}
		resp.UserAgentList = resultsUA
		fmt.Println("\t\tCompleted")
	}

	fmt.Print("Download current BotSifter filters to build comparison lists...")
	//List current Botsifter filters in GA account
	filters, err := service.Management.Filters.List(AccountID).Do()
	if err != nil {
		log.Fatalln(err)
	}

	var oldFilterListUA []Referrer
	var oldFilterListRef []Referrer
	var oldFilterListHost []Host

	for _, oldFilter := range filters.Items {
		if strings.Contains(oldFilter.Name, "BotSifter UA") == true {
			if filterExpression := oldFilter.ExcludeDetails; filterExpression != nil {
				filterExpression.ExpressionValue = (strings.Replace(filterExpression.ExpressionValue, "\\.", ".", -1))
				filterExpression.ExpressionValue = (strings.Replace(filterExpression.ExpressionValue, "\\+", "+", -1))
				for _, ref := range strings.Split(filterExpression.ExpressionValue, "|") {
					oldFilterListUA = append(oldFilterListUA, Referrer{ref, "", ""})
				}
			}
		}
		if strings.Contains(oldFilter.Name, "BotSifter Ref") == true {
			if filterExpression := oldFilter.ExcludeDetails; filterExpression != nil {
				filterExpression.ExpressionValue = (strings.Replace(filterExpression.ExpressionValue, "\\.", ".", -1))
				filterExpression.ExpressionValue = (strings.Replace(filterExpression.ExpressionValue, "\\+", "+", -1))
				for _, ref := range strings.Split(filterExpression.ExpressionValue, "|") {
					oldFilterListRef = append(oldFilterListRef, Referrer{ref, "", ""})
				}
			}
		}
		if strings.Contains(oldFilter.Name, "BotSifter Hostname") == true {
			if filterExpression := oldFilter.IncludeDetails; filterExpression != nil {
				filterExpression.ExpressionValue = (strings.Replace(filterExpression.ExpressionValue, "\\.", ".", -1))
				filterExpression.ExpressionValue = (strings.Replace(filterExpression.ExpressionValue, "\\+", "+", -1))
				for _, ref := range strings.Split(filterExpression.ExpressionValue, "|") {
					oldFilterListHost = append(oldFilterListHost, Host{ref})
				}
			}
		}

	}
	onlyInNewListRefs := Referrers(resp.ReferrerList).findEntriesOnlyInLeftSide(oldFilterListRef)
	onlyInOldListRefs := Referrers(oldFilterListRef).findEntriesOnlyInLeftSide(resp.ReferrerList)
	inBothListsRefs := Referrers(resp.ReferrerList).findInBoth(oldFilterListRef)

	onlyInNewListUAs := Referrers(resp.UserAgentList).findEntriesOnlyInLeftSide(oldFilterListUA)
	onlyInOldListUAs := Referrers(oldFilterListUA).findEntriesOnlyInLeftSide(resp.UserAgentList)
	inBothListsUAs := Referrers(resp.UserAgentList).findInBoth(oldFilterListUA)

	onlyInNewListHosts := Hosts(hosts).findEntriesOnlyInLeftSide(oldFilterListHost)
	onlyInOldListHosts := Hosts(oldFilterListHost).findEntriesOnlyInLeftSide(hosts)
	inBothListsHosts := Hosts(hosts).findInBoth(oldFilterListHost)

	var Ref Referrer
	resultsRef := []Referrer{}

	for _, Ref = range resp.ReferrerList {
		Ref.Referrer = (strings.Replace(Ref.Referrer, ".", "\\.", -1))
		Ref.Referrer = (strings.Replace(Ref.Referrer, "+", "\\+", -1))
		resultsRef = append(resultsRef, Ref)

	}
	resp.ReferrerList = resultsRef

	resultsUA := []Referrer{}
	for _, Ref = range resp.UserAgentList {
		Ref.Referrer = (strings.Replace(Ref.Referrer, ".", "\\.", -1))
		Ref.Referrer = (strings.Replace(Ref.Referrer, "+", "\\+", -1))
		resultsUA = append(resultsUA, Ref)

	}
	resp.UserAgentList = resultsUA

	resultsHost := []Host{}
	for _, h := range hosts {
		h.Hostname = (strings.Replace(h.Hostname, ".", "\\.", -1))
		h.Hostname = (strings.Replace(h.Hostname, "+", "\\+", -1))
		resultsHost = append(resultsHost, h)

	}
	hosts = resultsHost

	fmt.Println("\tCompleted")
	fmt.Println("")
	log.Println("Current Botsifter Bots:")
	log.Println("\n#################### CURRENT BotSifter BOTS ####################")
	log.Println("Referrers:\n")
	log.Println("\tRANK\tNAME\tSCORE")
	for _, Ref = range respDisplay.ReferrerList {
		log.Println(Ref)
	}
	log.Println("")
	log.Println("User Agents:\n")
	log.Println("\tRANK\tNAME\tSCORE")
	for _, Ref = range respDisplay.UserAgentList {
		log.Println(Ref)
	}
	log.Println("")
	log.Println("\nBotSifter will make the following changes to your GA Account[" + GooFig.UACode + "]:")
	log.Println("\n#################### HOST CHANGES ####################")
	log.Println("Added Hosts:\n")
	if onlyInNewListHosts != nil {
		sort.Sort(onlyInNewListHosts)
		for _, h := range onlyInNewListHosts {
			log.Println(h)
		}
	} else {
		log.Println("\tNONE")
	}
	log.Println("")
	log.Println("Removed Hosts:\n")
	if onlyInOldListHosts != nil {
		sort.Sort(onlyInOldListUAs)
		for _, h := range onlyInOldListHosts {
			log.Println(h)
		}
	} else {
		log.Println("\tNONE")
	}
	// log.Println(strings.Trim(fmt.Sprint(onlyInOldListRefs), "[]"))
	log.Println("")
	log.Println("Hosts unchange:\n")
	if inBothListsHosts != nil {
		sort.Sort(inBothListsUAs)
		for _, h := range inBothListsHosts {
			log.Println(h)
		}
	} else {
		log.Println("\tNONE")
	}

	log.Println("\n#################### REFERRER CHANGES ####################")
	log.Println("Added Referrers:\n")
	if onlyInNewListRefs != nil {
		log.Println("\tRANK\tNAME\tSCORE")
		sort.Sort(onlyInNewListRefs)
		for _, Ref = range onlyInNewListRefs {
			log.Println(Ref)
		}
	} else {
		log.Println("\tNONE")
	}
	log.Println("")
	log.Println("Removed Referrers:\n")
	if onlyInOldListRefs != nil {
		log.Println("\tRANK\tNAME\tSCORE")
		sort.Sort(onlyInOldListRefs)
		for _, Ref = range onlyInOldListRefs {
			log.Println(Ref)
		}
	} else {
		log.Println("\tNONE")
	}
	// log.Println(strings.Trim(fmt.Sprint(onlyInOldListRefs), "[]"))
	log.Println("")
	log.Println("Referrers unchange:\n")
	if inBothListsRefs != nil {
		log.Println("\tRANK\tNAME\tSCORE")
		sort.Sort(inBothListsRefs)
		for _, Ref = range inBothListsRefs {
			log.Println(Ref)
		}
	} else {
		log.Println("\tNONE")
	}
	log.Println("\n#################### USER AGENTS CHANGES ####################")
	log.Println("Added User Agents:\n")
	if onlyInNewListUAs != nil {
		log.Println("\tRANK\tNAME\tSCORE")
		sort.Sort(onlyInNewListUAs)
		for _, Ref = range onlyInNewListUAs {
			log.Println(Ref)
		}
	} else {
		log.Println("\tNONE")
	}
	log.Println("")
	log.Println("Removed User Agents:\n")
	if onlyInOldListUAs != nil {
		log.Println("\tRANK\tNAME\tSCORE")
		sort.Sort(onlyInOldListUAs)
		for _, Ref = range onlyInOldListUAs {
			log.Println(Ref)
		}
	} else {
		log.Println("\tNONE")
	}
	// log.Println(strings.Trim(fmt.Sprint(onlyInOldListRefs), "[]"))
	log.Println("")
	log.Println("User Agents unchange:\n")
	if inBothListsUAs != nil {
		log.Println("\tRANK\tNAME\tSCORE")
		sort.Sort(inBothListsUAs)
		for _, Ref = range inBothListsUAs {
			log.Println(Ref)
		}
	} else {
		log.Println("\tNONE")
	}
	w.Flush()
	// log.Println(strings.Trim(fmt.Sprint(inBothListsRefs), "[]"))
	log.Println("")

	if confirmFlag == false {

		length := len(filters.Items)
		var bar *pb.ProgressBar
		if length != 0 {
			bar = pb.StartNew(length)
			bar.SetMaxWidth(80)
			fmt.Println("Deleting old BotSifter filters ")
			for _, eachFilter := range filters.Items {

				if strings.Contains(eachFilter.Name, "BotSifter") == true {
					service.Management.Filters.Delete(AccountID, eachFilter.Id).Do()
				}
				bar.Increment()
				time.Sleep(time.Millisecond * 250)
			}
			bar.Finish()
		} else {
			fmt.Println("No filters to delete")
		}

		//If cleanFlag entered then end program here
		if cleanFlag == true {
			return
		}

		//If view is not defined in config file then ask user which one to apply filters too
		if GooFig.View == "" {
			//List all views
			profiles, err := service.Management.Profiles.List(AccountID, WebPropertyId).Do()
			if err != nil {
				log.Println(err)
			}

			for i, profile := range profiles.Items {
				fmt.Printf("%d. %s\n", i, profile.Name)
			}

			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Please select a profile to apply filters too: ")
			index := 0
			for {
				selectedProfileIndex, _ := reader.ReadString('\n')
				index, err = strconv.Atoi(strings.TrimSuffix(selectedProfileIndex, "\n"))
				if err == nil && index < len(profiles.Items) {
					break
				} else {
					fmt.Println("Invalid input", index, err)
				}
			}
			GooFig.View = profiles.Items[index].Id
		}
		//Prepare filters
		fmt.Println("Preparing Filter - combining multiple Referrers")
		var filterList []string
		filterList = RefMerge(resp.ReferrerList, true)

		//Build new filters from ReferrerList struct
		fmt.Println("Creating referral filters")
		var FilterIds []string
		length = len(filterList)
		bar = pb.StartNew(length)
		bar.SetMaxWidth(80)
		for i, newFilter := range filterList {
			counter := strconv.Itoa(i + 1)
			filter := &analytics.Filter{
				Name: "BotSifter Ref Spam" + counter,
				Type: "EXCLUDE",
				ExcludeDetails: &analytics.FilterExpression{
					Field:           "REFERRAL",
					ExpressionValue: newFilter,
					CaseSensitive:   false,
				},
			}
			filter, err = service.Management.Filters.Insert(AccountID, filter).Do()
			if err != nil {
				fmt.Print("\n")
				log.Println(err)
				return
			}
			//Save filter Ids for later
			FilterIds = append(FilterIds, filter.Id)
			bar.Increment()
			time.Sleep(time.Millisecond * 250)
		}
		bar.Finish()

		//Prepare filters
		fmt.Println("Preparing Filter - combining multiple User Agents")
		var filterListua []string
		filterListua = RefMerge(resp.UserAgentList, true)

		//Build new filters from ReferrerList struct
		fmt.Println("Creating User Agent filters")

		length = len(filterListua)
		bar = pb.StartNew(length)
		bar.SetMaxWidth(80)
		for i, newFilter := range filterListua {
			counter := strconv.Itoa(i + 1)
			filter := &analytics.Filter{
				Name: "BotSifter UA Spam" + counter,
				Type: "EXCLUDE",
				ExcludeDetails: &analytics.FilterExpression{
					Field:           "USER_DEFINED_VALUE",
					ExpressionValue: newFilter,
					CaseSensitive:   false,
				},
			}
			filter, err = service.Management.Filters.Insert(AccountID, filter).Do()

			if err != nil {
				fmt.Print("\n")
				fmt.Println(err)
				return
			}
			//Save filter Ids for later
			FilterIds = append(FilterIds, filter.Id)
			bar.Increment()
			time.Sleep(time.Millisecond * 250)
		}
		bar.Finish()

		if hosts != nil {
			var hostList []string
			hostList = HostMerge(hosts, false)

			//If there's hosts build "include Hostname" rule(s)
			fmt.Println("Creating Hostname filter(s)")
			length = len(hostList)
			bar = pb.StartNew(length)
			bar.SetMaxWidth(80)
			for i, newHost := range hostList {
				counter := strconv.Itoa(i)
				filter := &analytics.Filter{
					Name: "BotSifter Hostname Spam" + counter,
					Type: "INCLUDE",
					IncludeDetails: &analytics.FilterExpression{
						Field:           "PAGE_HOSTNAME",
						ExpressionValue: newHost,
						CaseSensitive:   false,
					},
				}

				filter, err = service.Management.Filters.Insert(AccountID, filter).Do()
				if err != nil {
					log.Println(err)
					return
				}

				//Save filter Ids for later
				FilterIds = append(FilterIds, filter.Id)
				bar.Increment()
				time.Sleep(time.Millisecond * 250)
			}
			bar.Finish()
		}

		//connecting built filters to profile user selected
		fmt.Println("Connecting filters to profile")
		length = len(FilterIds)
		bar = pb.StartNew(length)
		bar.SetMaxWidth(80)
		for _, newLink := range FilterIds {
			profilefilterlink := &analytics.ProfileFilterLink{
				FilterRef: &analytics.FilterRef{Id: newLink},
			}

			_, err := service.Management.ProfileFilterLinks.Insert(AccountID, WebPropertyId, GooFig.View, profilefilterlink).Do()
			if err != nil {
				log.Println("Error Connecting Filter to View\n")
			}
			bar.Increment()
			time.Sleep(time.Millisecond * 250)
		}
		bar.Finish()
	}
	fmt.Println("Saving configuration data to " + configFile)
	//Marshal data to save into config file
	data, err = yaml.Marshal(&GooFig)
	if err != nil {
		log.Println(err)
		return
	}

	//Write config file
	err = ioutil.WriteFile(configFile, data, 0644)

	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println("Completed")

}

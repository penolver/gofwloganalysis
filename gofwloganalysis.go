package main

import (
  "log"
  "fmt"
  "flag"
  "github.com/penolver/gofwloganalysis/parsers"
  "github.com/penolver/gofwloganalysis/app"
)

const version = "0.0.1"

func main() {

  fmt.Println(`
              _____      ____                         __         _
   ___ ____  / __/ | /| / / /__  ___ ____ ____  ___ _/ /_ _____ (_)__
  / _  / _ \/ _/ | |/ |/ / / _ \/ _  / _  / _ \/ _  / / // (_-</ (_-<
  \_, /\___/_/   |__/|__/_/\___/\_, /\_,_/_//_/\_,_/_/\_, /___/_/___/
 /___/  version `+version+`          /___/                 /___/
`)

  // log file to process
  logPtr := flag.String("l", "logfile.log", "the source log file, e.g. `logfile.log`")
  // type
  typePtr := flag.String("t", "vendor", "the source config file type, e.g. `vendor`, valid types include srx (only currently)")
  // list of interesting IP addresses to check for.. e.g. known malicious ip addresses (one per line, not a CSV)
  interestingIPPtr := flag.String("i", "some-bad-ips.txt", "the interesting IP's to look for (one per line, not a CSV), e.g. `some-bad-ips.txt`")

  flag.Parse()

  if *logPtr == "logfile.log" {
    flag.PrintDefaults()
    fmt.Println()
    log.Fatal("ERROR, missing arguments")
  }
  if *typePtr == "vendor" {
    flag.PrintDefaults()
    fmt.Println()
    log.Fatal("ERROR, missing arguments")
  }
  if *interestingIPPtr == "some-bad-ips.txt" {
    flag.PrintDefaults()
    fmt.Println()
    log.Fatal("ERROR, missing arguments")
  }


  usedpolicies := make(map[string]int)
  interestingIPs := make(map[string]string)
  suspecttraffic := make(map[string]string)


  if *interestingIPPtr != "some-bad-ips.txt" {
    log.Println("Processing interesting IP list..")
    interestingIPs = app.ParseThreatData(*interestingIPPtr)
  }

  //ruletracker := make(map[int]string)
  if *typePtr == "srx" {
    log.Println("Processing SRX log..")
    usedpolicies,suspecttraffic = parsers.ProcessSRXLog(*logPtr,interestingIPs)

  }else {
    log.Fatal("Unsupported config type, exiting.")
  }

  fmt.Println("Used Policies...")
  // should do this as a nice CSV (next version!)
  for policyname,count := range usedpolicies {
    fmt.Println("Policy: ",policyname," | Count: ",count)
  }
  fmt.Println("Suspect Traffic...")
  // should do this as a nice CSV (next version!)
  for ip,detail := range suspecttraffic {
    fmt.Println("IP: ",ip," | Detail: ",detail)
  }

}

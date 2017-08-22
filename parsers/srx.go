package parsers

import (
  "gopkg.in/cheggaaa/pb.v1"
  "log"
  "os"
  "bufio"
  //"strings"
  "regexp"
)

func ProcessSRXLog(filename string,interestingIPs map[string]string) (map[string]int,map[string]string) {

  suspecttraffic := make(map[string]string)

  linesinfile,_ := LineCounter(filename)
  log.Println("Lines in log file to process: ",linesinfile)
  log.Println("Processing SRX log file...")

  bar := pb.StartNew(linesinfile)

  file, err := os.Open(filename)
  if err != nil {
    log.Fatal("Error:", err)
  }
  // automatically call Close() at the end of current method
  defer file.Close()
  // create a new scanner and read the file line by line
  scanner := bufio.NewScanner(file)

  usedpolicies := make(map[string]int)
  var sourcezone,destzone,policyname string

  regexline, err := regexp.Compile(`RT_FLOW: (RT_FLOW_SESSION_DENY: session denied|RT_FLOW_SESSION_CREATE: session created|RT_FLOW_SESSION_CLOSE: session closed TCP FIN:|RT_FLOW_SESSION_CLOSE: session closed idle Timeout N/A:|RT_FLOW_SESSION_CLOSE: session closed TCP CLIENT RST:) ([0-9,.]*)/([0-9]*)->([0-9,.]*)/([0-9]*) (?:0x0) ([a-zA-Z,0-9,\-,\_]*)(?: [0-9,.]*)?(?:/)?(?:[0-9]*)?(?:->)?(?:[0-9,.]*)?(?:/)?(?:[0-9]*)?(?: 0x0)?(?: [a-zA-Z,\-,\_,/]*)?(?: [a-zA-Z,\-,\_,/]*)?(?: [a-zA-Z,\-,\_,/]*)?(?: [a-zA-Z,\-,\_,/]*)?(?: [a-zA-Z,0-9,\-,\_,/,\(,\)]*)?( [a-zA-Z,0-9,\-,\_]*)?( [a-zA-Z,0-9,\-,\_]*)?( [a-zA-Z,0-9,\-,\_]*)?`)

  for scanner.Scan() {

    if matches := regexline.FindStringSubmatch(scanner.Text()); matches != nil {

      if _, ok := interestingIPs[matches[2]]; ok {
        suspecttraffic[matches[2]] = scanner.Text()
      }
      if _, ok := interestingIPs[matches[4]]; ok {
        suspecttraffic[matches[4]] = scanner.Text()
      }

      // if its a deny..
      if matches[1] == "RT_FLOW_SESSION_DENY: session denied" {

        // ignore for now..

      // otherwise allowed (log on session open or close)
      }else{

        sourcezone = matches[8]
        destzone = matches[9]
        policyname = matches[7]

        usedpolicies[sourcezone+" -> "+destzone+" : "+policyname] = usedpolicies[sourcezone+" -> "+destzone+" : "+policyname] + 1

      }

    }

    bar.Increment()

  }
  bar.FinishPrint("Finished Processing and Analysing Log file")

  return usedpolicies,suspecttraffic

}

package app

import (
	"log"
  "bufio"
	"os"
	"gopkg.in/cheggaaa/pb.v1"
  "github.com/penolver/gofwloganalysis/parsers"
)

func ParseThreatData(path string) (map[string]string) {

	threatIPDomain := make(map[string]string)

  linesinfile,_ := parsers.LineCounter(path)
  log.Println("Lines in threat file to process: ",linesinfile)

  bar := pb.StartNew(linesinfile)

  file, err := os.Open(path)
  if err != nil {
    log.Fatal("Error:", err)
  }
  defer file.Close()
  // create a new scanner and read the file line by line
  scanner := bufio.NewScanner(file)

  for scanner.Scan() {

    threatIPDomain[scanner.Text()] = scanner.Text()
    bar.Increment()

  }
  bar.FinishPrint("Finished Processing interesting IP list")

	return threatIPDomain
}

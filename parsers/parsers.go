package parsers

import (
  "log"
  //"fmt"
  "os"
  "bytes"
  "io"
)

type FWRule struct {
  RuleName string
  Allowdeny string
  Disabled  bool
  SourceZone string
  Sources []string
}

// count number of lines in file
func LineCounter(path string) (int, error) {
    buf := make([]byte, 32*1024)
    count := 0
    lineSep := []byte{'\n'}

    r, err := os.Open(path)
  	if err != nil {
  		log.Fatal("File Missing. ", err)
  	}

    for {
        c, err := r.Read(buf)
        count += bytes.Count(buf[:c], lineSep)

        switch {
        case err == io.EOF:
            return count, nil

        case err != nil:
            return count, err
        }
    }
} // LineCounter

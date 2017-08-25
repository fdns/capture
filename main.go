package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/google/gopacket/layers"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

var devName = flag.String("devName", "", "Device used to capture")

var outChannel chan []string

func showDNS(dns layers.DNS, SrcIP string, DstIP string, protocol string) {
	for _, dnsQuestion := range dns.Questions {
		w := csv.NewWriter(os.Stdout)
		outChannel <- []string{protocol, SrcIP, DstIP, strconv.FormatBool(dns.QR), strconv.Itoa(int(dns.OpCode)), strconv.Itoa(int(dns.ResponseCode)), strconv.Itoa(int(dns.ANCount)), string(dnsQuestion.Name)}
		w.Flush()
	}
}

func output(exiting chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()
	ticker := time.Tick(time.Second)
	for {
		select {
		case data := <-outChannel:
			w.Write(data)
		case <-ticker:
			w.Flush()
		case <-exiting:
			return
		}
	}
}

func main() {
	flag.Parse()
	if *devName == "" {
		log.Fatal("-devName is required")
	}
	outChannel = make(chan []string, 100)

	// Setup output routine
	exiting := make(chan bool)
	var wg sync.WaitGroup
	go output(exiting, &wg)

	// Start listening
	start(*devName, showDNS)

	// Wait for the output to finish
	fmt.Println("Exiting")
	close(exiting)
	wg.Wait()
}

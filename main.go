package main

import (
	"container/list"
	"database/sql"
	"flag"
	"fmt"
	"github.com/google/gopacket/layers"
	"log"
	"sync"
	"time"

	"github.com/kshvakov/clickhouse"
)

var devName = flag.String("devName", "", "Device used to capture")

var outChannel chan []interface{}

func showDNS(dns layers.DNS, SrcIP string, DstIP string, protocol string) {
	for _, dnsQuestion := range dns.Questions {
		outChannel <- []interface{}{
			time.Now(),
			protocol,
			SrcIP,
			DstIP,
			dns.QR,
			int(dns.OpCode),
			int(dns.ResponseCode),
			int(dns.ANCount),
			string(dnsQuestion.Name)}
	}
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func connect_clickhouse() *sql.DB {
	connect, err := sql.Open("clickhouse", "tcp://172.30.65.172:9000?username=&compress=true&debug=true")
	checkErr(err)
	if err := connect.Ping(); err != nil {
		if exception, ok := err.(*clickhouse.Exception); !ok {
			log.Fatal(exception)
		}
	}

	_, err = connect.Exec(`
		CREATE TABLE IF NOT EXISTS DNS_LOG (
			DnsDate Date,
			timestamp DateTime,
			Protocol FixedString(3),
			QR UInt8,
			OpCode UInt8,
			ResponceCode UInt8,
			Question String
		) engine=MergeTree(DnsDate, (timestamp, Question), 8192)
		`)
	checkErr(err)
	return connect
}

func output(exiting chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	connect := connect_clickhouse()
	batch := list.New()

	ticker := time.Tick(time.Second)
	for {
		select {
		case data := <-outChannel:
			batch.PushBack(data)
		case <-ticker:
			if batch.Len() > 0 {
				tx, err := connect.Begin()
				checkErr(err)
				stmt, err := tx.Prepare("INSERT INTO DNS_LOG (DnsDate, timestamp, Protocol, QR, OpCode, ResponceCode, Question) VALUES(?,?,?,?,?,?,?)")
				checkErr(err)
				for iter := batch.Front(); iter != nil; iter = iter.Next() {
					item := iter.Value.([]interface{})
					if _, err := stmt.Exec(item[0], item[0], item[1], item[4], item[5], item[6], item[8]); err != nil {
						log.Fatal(err)
					}
				}
				checkErr(tx.Commit())
				batch.Init()
			}
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
	outChannel = make(chan []interface{}, 1000)

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

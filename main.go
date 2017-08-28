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

	_ "github.com/kshvakov/clickhouse"
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

func connectClickhouse() *sql.DB {
	tick := time.Tick(5 * time.Second)
	for {
		select {
		case <-tick:
			connection, err := sql.Open("clickhouse", "tcp://172.30.65.172:9000?username=&compress=true&debug=false")
			if err != nil {
				log.Println(err)
				continue
			}
			// SELECT t, groupArray((Question, c)) as groupArr FROM (SELECT (intDiv(toUInt32(toStartOfMinute(timestamp)), 10) * 10) * 1000 as t, Question, count(*) as c FROM $table WHERE $timeFilter GROUP BY t, Question ORDER BY t limit 5 by t ) GROUP BY t order by t
			// CREATE MATERIALIZED VIEW grouped_query ENGINE=SummingMergeTree(DnsDate, (t, Question), 8192, c) AS SELECT DnsDate, toStartOfMinute(timestamp) as t, Question, count(*) as c FROM DNS_LOG GROUP BY t, Question
			_, err = connection.Exec(`
			CREATE TABLE IF NOT EXISTS DNS_LOG (
				DnsDate Date,
				timestamp DateTime,
				Protocol FixedString(3),
				QR UInt8,
				OpCode UInt8,
				ResponceCode UInt8,
				Question String
			) engine=MergeTree(DnsDate, (timestamp, Question, Protocol), 8192)
			`)
			if err != nil {
				log.Println(err)
				continue
			}
			_, err = connection.Exec(`
			CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_DOMAIN_COUNT
		  	ENGINE=SummingMergeTree(DnsDate, (t, Question), 8192, c) AS
		  	SELECT DnsDate, toStartOfMinute(timestamp) as t, Question, count(*) as c FROM DNS_LOG GROUP BY DnsDate, t, Question
			`)
			if err != nil {
				log.Println(err)
				continue
			}
			return connection
		}
	}
}

func output(exiting chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	connect := connectClickhouse()
	batch := list.New()

	ticker := time.Tick(time.Second)
	for {
		select {
		case data := <-outChannel:
			batch.PushBack(data)
		case <-ticker:
			if batch.Len() > 0 {
				for {
					tx, err := connect.Begin()
					if err != nil {
						log.Println(err)
						connect = connectClickhouse()
						continue
					}
					stmt, err := tx.Prepare("INSERT INTO DNS_LOG (DnsDate, timestamp, Protocol, QR, OpCode, ResponceCode, Question) VALUES(?,?,?,?,?,?,?)")
					if err != nil {
						log.Println(err)
						connect = connectClickhouse()
						continue
					}
					fmt.Println(batch.Len())
					for iter := batch.Front(); iter != nil; iter = iter.Next() {
						item := iter.Value.([]interface{})
						if _, err := stmt.Exec(item[0], item[0], item[1], item[4], item[5], item[6], item[8]); err != nil {
							if err != nil {
								log.Println(err)
								connect = connectClickhouse()
								continue
							}
						}
					}
					err = tx.Commit()
					if err != nil {
						log.Println(err)
						connect = connectClickhouse()
						continue
					}
					batch.Init()
					break
				}
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
	outChannel = make(chan []interface{}, 10000)

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

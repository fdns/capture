package main

import (
	"container/list"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/kshvakov/clickhouse"
)

var devName = flag.String("devName", "", "Device used to capture")
var packetHandlerCount = flag.Uint("packetHandlers", 1, "Number of routines used to handle received packets")
var tcpHandlerCount = flag.Uint("tcpHandlers", 1, "Number of routines used to handle tcp assembly")

func connectClickhouse(exiting chan bool) *sql.DB {
	tick := time.NewTimer(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-exiting:
			// When exiting, return inmediatly
			return nil
		case <-tick.C:
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

func output(resultChannel chan DnsResult, exiting chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	connect := connectClickhouse(exiting)
	batch := list.New()

	ticker := time.Tick(time.Second)
	for {
		select {
		case data := <-resultChannel:
			batch.PushBack(data)
		case <-ticker:
			if batch.Len() > 0 {
			PROCESS:
				for {
					// Return if the connection is null, we are exiting
					if connect == nil {
						break
					}
					tx, err := connect.Begin()
					if err != nil {
						log.Println(err)
						connect = connectClickhouse(exiting)
						continue
					}
					stmt, err := tx.Prepare("INSERT INTO DNS_LOG (DnsDate, timestamp, Protocol, QR, OpCode, ResponceCode, Question) VALUES(?,?,?,?,?,?,?)")
					if err != nil {
						log.Println(err)
						connect = connectClickhouse(exiting)
						continue
					}
					fmt.Println(batch.Len())
					for iter := batch.Front(); iter != nil; iter = iter.Next() {
						item := iter.Value.(DnsResult)
						for _, dnsQuestion := range item.dns.Questions {
							if _, err := stmt.Exec(item.timestamp,
								item.timestamp,
								item.protocol, item.dns.QR,
								int(item.dns.ResponseCode),
								int(item.dns.ResponseCode),
								string(dnsQuestion.Name)); err != nil {
								if err != nil {
									log.Println(err)
									connect = connectClickhouse(exiting)
									continue PROCESS
								}
							}
						}
					}
					err = tx.Commit()
					if err != nil {
						log.Println(err)
						connect = connectClickhouse(exiting)
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
	resultChannel := make(chan DnsResult, 10000)

	// Setup output routine
	exiting := make(chan bool)
	var wg sync.WaitGroup
	go output(resultChannel, exiting, &wg)

	// Start listening
	start(*devName, resultChannel, *packetHandlerCount, *tcpHandlerCount, exiting)

	// Wait for the output to finish
	fmt.Println("Exiting")
	wg.Wait()
}

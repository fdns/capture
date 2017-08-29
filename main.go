package main

import (
	"container/list"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"
	"runtime/pprof"

	_ "github.com/kshvakov/clickhouse"
	"os"
	"runtime"
)

var devName = flag.String("devName", "", "Device used to capture")
var packetHandlerCount = flag.Uint("packetHandlers", 2, "Number of routines used to handle received packets")
var tcpHandlerCount = flag.Uint("tcpHandlers", 1, "Number of routines used to handle tcp assembly")
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var memprofile = flag.String("memprofile", "", "write memory profile to `file`")

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
			_, err = connection.Exec(`
			CREATE TABLE IF NOT EXISTS DNS_LOG (
				DnsDate Date,
				timestamp DateTime,
				Protocol FixedString(3),
				QR UInt8,
				OpCode UInt8,
				ResponceCode UInt8,
				Question String,
				Size UInt16
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
					stmt, err := tx.Prepare("INSERT INTO DNS_LOG (DnsDate, timestamp, Protocol, QR, OpCode, ResponceCode, Question, Size) VALUES(?,?,?,?,?,?,?,?)")
					if err != nil {
						log.Println(err)
						connect = connectClickhouse(exiting)
						continue
					}
					fmt.Println(batch.Len())
					for iter := batch.Front(); iter != nil; iter = iter.Next() {
						item := iter.Value.(DnsResult)
						for _, dnsQuestion := range item.Dns.Questions {
							if _, err := stmt.Exec(item.timestamp,
								item.timestamp,
								item.Protocol,
								item.Dns.QR,
								int(item.Dns.OpCode),
								int(item.Dns.ResponseCode),
								string(dnsQuestion.Name),
								item.PacketLength); err != nil {
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
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if *devName == "" {
		log.Fatal("-devName is required")
	}
	resultChannel := make(chan DnsResult, 100000)

	// Setup output routine
	exiting := make(chan bool)
	var wg sync.WaitGroup
	go output(resultChannel, exiting, &wg)

	// Start listening
	start(*devName, resultChannel, *packetHandlerCount, *tcpHandlerCount, exiting)


	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
		f.Close()
	}

	// Wait for the output to finish
	fmt.Println("Exiting")
	wg.Wait()
}

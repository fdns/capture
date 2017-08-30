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
	"strings"
)

var devName = flag.String("devName", "", "Device used to capture")
var packetHandlerCount = flag.Uint("packetHandlers", 1, "Number of routines used to handle received packets")
var tcpHandlerCount = flag.Uint("tcpHandlers", 1, "Number of routines used to handle tcp assembly")
var packetChannelSize = flag.Uint("packetHandlerChannelSize", 1000000, "Size of the packet handler channel size")
var resultChannelSize = flag.Uint("resultChannelSize", 1000000, "Size of the result processor channel size")
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
				Class UInt16,
				Type UInt16,
				ResponceCode UInt8,
				Question String,
				SourceIPMask FixedString(15),
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
			if err := SendData(connect, batch, exiting); err != nil {
				log.Println(err)
				connect = connectClickhouse(exiting)
			}
		case <-exiting:
			return
		}
	}
}

func SendData(connect *sql.DB, batch *list.List, exiting chan bool) error {
	if batch.Len() == 0 {
		return nil
	}
	// Return if the connection is null, we are exiting
	if connect == nil {
		return nil
	}
	tx, err := connect.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO DNS_LOG (DnsDate, timestamp, Protocol, QR, OpCode, Class, Type, ResponceCode, Question, SourceIPMask, Size) VALUES(?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	fmt.Println(batch.Len())
	for iter := batch.Front(); iter != nil; iter = iter.Next() {
		item := iter.Value.(DnsResult)
		srcIpMask := strings.Split(item.SrcIP, ".")[0] + ".0.0.0"
		for _, dnsQuestion := range item.Dns.Questions {
			if _, err := stmt.Exec(item.timestamp,
				item.timestamp,
				item.Protocol,
				item.Dns.QR,
				int(item.Dns.OpCode),
				int(dnsQuestion.Class),
				int(dnsQuestion.Type),
				int(item.Dns.ResponseCode),
				string(dnsQuestion.Name),
				srcIpMask,
				item.PacketLength); err != nil {
				if err != nil {
					return err
				}
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	batch.Init()
	return nil
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
	resultChannel := make(chan DnsResult, *resultChannelSize)

	// Setup output routine
	exiting := make(chan bool)
	var wg sync.WaitGroup
	go output(resultChannel, exiting, &wg)

	go func() {
		time.Sleep(50*time.Second)
		if *memprofile != "" {
			fmt.Println("Writing mem")
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
	}()

	// Start listening
	start(*devName, resultChannel, *packetHandlerCount, *packetChannelSize, *tcpHandlerCount, exiting)


	// Wait for the output to finish
	fmt.Println("Exiting")
	wg.Wait()
}

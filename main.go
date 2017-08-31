package main

import (
	"database/sql/driver"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"
	"runtime/pprof"

	"os"
	"runtime"
	_ "github.com/kshvakov/clickhouse"
	data "github.com/kshvakov/clickhouse/lib/data"
	"github.com/kshvakov/clickhouse"
	"strings"
)

var devName = flag.String("devName", "", "Device used to capture")
var packetHandlerCount = flag.Uint("packetHandlers", 1, "Number of routines used to handle received packets")
var tcpHandlerCount = flag.Uint("tcpHandlers", 1, "Number of routines used to handle tcp assembly")
var packetChannelSize = flag.Uint("packetHandlerChannelSize", 1000000, "Size of the packet handler channel size")
var resultChannelSize = flag.Uint("resultChannelSize", 1000000, "Size of the result processor channel size")
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var memprofile = flag.String("memprofile", "", "write memory profile to `file`")


func connectClickhouse(exiting chan bool) clickhouse.Clickhouse {
	tick := time.NewTimer(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-exiting:
			// When exiting, return inmediatly
			return nil
		case <-tick.C:
			connection, err := clickhouse.OpenDirect("tcp://172.30.65.172:9000?username=&compress=true&debug=false")
			if err != nil {
				log.Println(err)
				continue
			}
			{
				stmt, _ := connection.Prepare(`
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
				SourceIPMask String,
				Size UInt16
			) engine=MergeTree(DnsDate, (timestamp, Question, Protocol), 8192)
			`)
				if _, err := stmt.Exec([]driver.Value{}); err != nil {
					log.Println(err)
					continue
				}
				connection.Commit()
			}
			{
				stmt, _ := connection.Prepare(`
				CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_DOMAIN_COUNT
				ENGINE=SummingMergeTree(DnsDate, (t, Question), 8192, c) AS
				SELECT DnsDate, toStartOfMinute(timestamp) as t, Question, count(*) as c FROM DNS_LOG GROUP BY DnsDate, t, Question
				`)

				if _, err := stmt.Exec([]driver.Value{}); err != nil {
					log.Println(err)
					continue
				}
				connection.Commit()
			}
			return connection
		}
	}
}

func output(resultChannel chan DnsResult, exiting chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	connect := connectClickhouse(exiting)
	batch := make([]DnsResult, 0, 200000)

	ticker := time.Tick(time.Second)
	for {
		select {
		case data := <-resultChannel:
			batch = append(batch, data)
		case <-ticker:
			if err := SendData(connect, batch, exiting); err != nil {
				log.Println(err)
				connect = connectClickhouse(exiting)
			}
			batch = make([]DnsResult, 0, 200000)
		case <-exiting:
			return
		}
	}
}

func min(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func SendData(connect clickhouse.Clickhouse, batch []DnsResult, exiting chan bool) error {
	if len(batch) == 0 {
		return nil
	}
	fmt.Println(len(batch))

	// Return if the connection is null, we are exiting
	if connect == nil {
		return nil
	}
	_, err := connect.Begin()
	if err != nil {
		return err
	}

	_, err = connect.Prepare("INSERT INTO DNS_LOG (DnsDate, timestamp, Protocol, QR, OpCode, Class, Type, ResponceCode, Question, SourceIPMask, Size) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}

	block, err := connect.Block()
	if err != nil {
		return err
	}

	blocks := []*data.Block{block, block.Copy()}

	count := len(blocks)
	var wg sync.WaitGroup
	wg.Add(len(blocks))
	for i := range blocks {
		b := blocks[i]
		start := i*(len(batch))/count
		end := min((i+1)*(len(batch))/count, len(batch))

		go func() {
			defer wg.Done()
			b.Reserve()
			for k := start; k < end; k++ {
				for _, dnsQuery := range batch[k].Dns.Questions {
					b.NumRows++
					srcIpMask := strings.Split(batch[k].SrcIP, ".")[0] + ".0.0.0"
					b.WriteDate(0, batch[k].timestamp)
					b.WriteDateTime(1, batch[k].timestamp)
					b.WriteFixedString(2, []byte(batch[k].Protocol))
					QR := uint8(0)
					if batch[k].Dns.QR {
						QR = 1
					}
					b.WriteUInt8(3, QR)
					b.WriteUInt8(4, uint8(batch[k].Dns.OpCode))
					b.WriteUInt16(5, uint16(dnsQuery.Class))
					b.WriteUInt16(6, uint16(dnsQuery.Type))
					b.WriteUInt8(7, uint8(batch[k].Dns.ResponseCode))
					b.WriteString(8, string(dnsQuery.Name))
					b.WriteString(9, srcIpMask)
					b.WriteUInt16(10, batch[k].PacketLength)
					break
				}
			}
			if err := connect.WriteBlock(b); err != nil {
				log.Fatal(err)
			}
		}()
	}

	wg.Wait()
	if err := connect.Commit(); err != nil {
		log.Fatal(err)
	}

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

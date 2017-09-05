package main

import (
	"database/sql/driver"
	"flag"
	"fmt"
	"log"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/kshvakov/clickhouse"
	_ "github.com/kshvakov/clickhouse"
	data "github.com/kshvakov/clickhouse/lib/data"
	"os"
	"runtime"
	"encoding/binary"
	"net"
)

var devName = flag.String("devName", "", "Device used to capture")
var filter = flag.String("filter", "(tcp or udp) and port 53", "BPF filter applied to the packet stream")
var clickhouseAddress = flag.String("clickhouseAddress", "localhost:9000", "Address of the clickhouse database to save the results")
var batchSize = flag.Uint("batchSize", 100000, "Minimun capacity of the cache array used to send data to clickhouse. Set close to the queries per second received to prevent allocations")
var packetHandlerCount = flag.Uint("packetHandlers", 1, "Number of routines used to handle received packets")
var tcpHandlerCount = flag.Uint("tcpHandlers", 1, "Number of routines used to handle tcp assembly")
var packetChannelSize = flag.Uint("packetHandlerChannelSize", 100000, "Size of the packet handler channel")
var tcpAssemblyChannelSize = flag.Uint("tcpAssemblyChannelSize", 1000, "Size of the tcp assembler")
var tcpResultChannelSize = flag.Uint("tcpResultChannelSize", 1000, "Size of the tcp result channel")
var resultChannelSize = flag.Uint("resultChannelSize", 100000, "Size of the result processor channel size")
var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
var memprofile = flag.String("memprofile", "", "write memory profile to `file`")


func connectClickhouseRetry(exiting chan bool, clickhouseHost string) clickhouse.Clickhouse {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		c, err := connectClickhouse(exiting, clickhouseHost)
		if err == nil {
			return c
		}

		// Error getting connection, wait the timer or check if we are exiting
		select {
		case <-exiting:
			// When exiting, return immediately
			return nil
		case <-tick.C:
			continue
		}
	}
}

func connectClickhouse(exiting chan bool, clickhouseHost string) (clickhouse.Clickhouse, error) {
	connection, err := clickhouse.OpenDirect(fmt.Sprintf("tcp://%v?username=&compress=true&debug=false", clickhouseHost))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	{
		stmt, _ := connection.Prepare(`
	CREATE TABLE IF NOT EXISTS DNS_LOG (
		DnsDate Date,
		timestamp DateTime,
		IPVersion UInt8,
		IPPrefix UInt32,
		Protocol FixedString(3),
		QR UInt8,
		OpCode UInt8,
		Class UInt16,
		Type UInt16,
		ResponceCode UInt8,
		Question String,
		Size UInt16
	) engine=MergeTree(DnsDate, (timestamp, IPVersion), 8192)
	`)
		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the top queried domains
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_DOMAIN_COUNT
		ENGINE=SummingMergeTree(DnsDate, (t, Question), 8192, c) AS
		SELECT DnsDate, toStartOfMinute(timestamp) as t, Question, count(*) as c FROM DNS_LOG GROUP BY DnsDate, t, Question
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the unique domain count
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_DOMAIN_UNIQUE
		ENGINE=AggregatingMergeTree(DnsDate, (timestamp), 8192) AS
		SELECT DnsDate, timestamp, uniqState(Question) AS UniqueDnsCount FROM DNS_LOG GROUP BY DnsDate, timestamp
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by protocol
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_PROTOCOL
		ENGINE=SummingMergeTree(DnsDate, (timestamp, Protocol), 8192, (c, Size)) AS
		SELECT DnsDate, timestamp, Protocol, count(*) as c FROM DNS_LOG GROUP BY DnsDate, timestamp, Protocol
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to aggregate packet size
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_PACKET_SIZE
		ENGINE=AggregatingMergeTree(DnsDate, (timestamp), 8192) AS
		SELECT DnsDate, timestamp, sumState(Size) AS TotalSize, avgState(Size) AS AverageSize FROM DNS_LOG GROUP BY DnsDate, timestamp
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by OpCode
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_OPCODE
		ENGINE=SummingMergeTree(DnsDate, (timestamp, OpCode), 8192, c) AS
		SELECT DnsDate, timestamp, OpCode, count(*) as c FROM DNS_LOG GROUP BY DnsDate, timestamp, OpCode
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by Query Type
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_TYPE
		ENGINE=SummingMergeTree(DnsDate, (timestamp, Type), 8192, c) AS
		SELECT DnsDate, timestamp, Type, count(*) as c FROM DNS_LOG GROUP BY DnsDate, timestamp, Type
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by Query Class
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_CLASS
		ENGINE=SummingMergeTree(DnsDate, (timestamp, Class), 8192, c) AS
		SELECT DnsDate, timestamp, Class, count(*) as c FROM DNS_LOG GROUP BY DnsDate, timestamp, Class
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	// View to fetch the querys by Responce
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_RESPONCECODE
		ENGINE=SummingMergeTree(DnsDate, (timestamp, ResponceCode), 8192, c) AS
		SELECT DnsDate, timestamp, ResponceCode, count(*) as c FROM DNS_LOG GROUP BY DnsDate, timestamp, ResponceCode
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	{
		stmt, _ := connection.Prepare(`
		CREATE MATERIALIZED VIEW IF NOT EXISTS DNS_RESPONCECODE
		ENGINE=SummingMergeTree(DnsDate, (timestamp, ResponceCode), 8192, c) AS
		SELECT DnsDate, timestamp, ResponceCode, count(*) as c FROM DNS_LOG GROUP BY DnsDate, timestamp, ResponceCode
		`)

		if _, err := stmt.Exec([]driver.Value{}); err != nil {
			log.Println(err)
			return nil, err
		}
		connection.Commit()
	}
	return connection, nil
}

func output(resultChannel chan DnsResult, exiting chan bool, wg *sync.WaitGroup, clickhouseHost string, batchSize uint) {
	wg.Add(1)
	defer wg.Done()

	connect := connectClickhouseRetry(exiting, clickhouseHost)
	batch := make([]DnsResult, 0, batchSize)

	ticker := time.Tick(time.Second)
	for {
		select {
		case data := <-resultChannel:
			batch = append(batch, data)
		case <-ticker:
			if err := SendData(connect, batch); err != nil {
				log.Println(err)
				connect = connectClickhouseRetry(exiting, clickhouseHost)
			} else {
				batch = make([]DnsResult, 0, batchSize)
			}
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

func SendData(connect clickhouse.Clickhouse, batch []DnsResult) error {
	if len(batch) == 0 {
		return nil
	}

	// Return if the connection is null, we are exiting
	if connect == nil {
		return nil
	}
	log.Println("Sending ", len(batch))

	_, err := connect.Begin()
	if err != nil {
		return err
	}

	_, err = connect.Prepare("INSERT INTO DNS_LOG (DnsDate, timestamp, IPVersion, IPPrefix, Protocol, QR, OpCode, Class, Type, ResponceCode, Question, Size) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}

	block, err := connect.Block()
	if err != nil {
		return err
	}

	blocks := []*data.Block{block}

	count := len(blocks)
	var wg sync.WaitGroup
	wg.Add(len(blocks))
	for i := range blocks {
		b := blocks[i]
		start := i * (len(batch)) / count
		end := min((i+1)*(len(batch))/count, len(batch))

		go func() {
			defer wg.Done()
			b.Reserve()
			for k := start; k < end; k++ {
				for _, dnsQuery := range batch[k].Dns.Questions {
					b.NumRows++
					b.WriteDate(0, batch[k].timestamp)
					b.WriteDateTime(1, batch[k].timestamp)
					b.WriteUInt8(2, batch[k].IPVersion)

					ip := batch[k].DstIP
					if batch[k].IPVersion == 4 {
						ip = ip.Mask(net.IPv4Mask(0xff, 0, 0, 0))
					}
					b.WriteUInt32(3, binary.BigEndian.Uint32(ip[:4]))
					b.WriteFixedString(4, []byte(batch[k].Protocol))
					QR := uint8(0)
					if batch[k].Dns.QR {
						QR = 1
					}
					b.WriteUInt8(5, QR)
					b.WriteUInt8(6, uint8(batch[k].Dns.OpCode))
					b.WriteUInt16(7, uint16(dnsQuery.Class))
					b.WriteUInt16(8, uint16(dnsQuery.Type))
					b.WriteUInt8(9, uint8(batch[k].Dns.ResponseCode))
					b.WriteString(10, string(dnsQuery.Name))
					b.WriteUInt16(11, batch[k].PacketLength)
				}
			}
			if err := connect.WriteBlock(b); err != nil {
				return
			}
		}()
	}

	wg.Wait()
	if err := connect.Commit(); err != nil {
		return err
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
	go output(resultChannel, exiting, &wg, *clickhouseAddress, *batchSize)

	go func() {
		time.Sleep(120 * time.Second)
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
	start(*devName, *filter, resultChannel, *packetHandlerCount, *packetChannelSize, *tcpHandlerCount, *tcpAssemblyChannelSize, *tcpResultChannelSize, exiting)

	// Wait for the output to finish
	fmt.Println("Exiting")
	wg.Wait()
}

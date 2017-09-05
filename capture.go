package main

import (
	"fmt"
	"log"
	"time"

	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	mkdns "github.com/miekg/dns"
	"io"
	"os"
	"os/signal"
	"net"
)

type DnsHandler func(dns layers.DNS, SrcIP string, DstIP string, protocol string)
type DnsResult struct {
	timestamp    time.Time
	Dns          mkdns.Msg
	IPVersion    uint8
	SrcIP        net.IP
	DstIP        net.IP
	Protocol     string
	PacketLength uint16
}

type tcpPacket struct {
	IPVersion uint8
	packet    gopacket.Packet
	Timestamp time.Time
}

type tcpData struct {
	IPVersion uint8
	data   []byte
	SrcIp  net.IP
	DstIp  net.IP
}

type dnsStreamFactory struct {
	tcp_return_channel chan tcpData
	IPVersion uint8
}

type dnsStream struct {
	Net                gopacket.Flow
	reader             tcpreader.ReaderStream
	tcp_return_channel chan tcpData
	IPVersion uint8
}

func (ds *dnsStream) processStream() {
	var data []byte
	var tmp = make([]byte, 4096)

	for {
		count, err := ds.reader.Read(tmp)

		if err == io.EOF {
			return
		} else if err != nil {
			fmt.Errorf("Error when reading DNS buf", err)
		} else if count > 0 {
			data = append(data, tmp[0:count]...)
			for curLength := len(data); curLength >= 2; curLength = len(data) {
				expected := int(binary.BigEndian.Uint16(data[:2])) + 2
				if curLength+count >= expected {
					result := data[2:expected]

					// Send the data to be processed
					ds.tcp_return_channel <- tcpData{
						IPVersion: ds.IPVersion,
						data:  result,
						SrcIp: net.IP(ds.Net.Src().Raw()),
						DstIp: net.IP(ds.Net.Dst().Raw()),
					}
					// Save the remaining data for future querys
					data = data[expected:]
				} else {
					break
				}
			}
		}
	}
}

func (stream *dnsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	dstream := &dnsStream{
		Net:                net,
		reader:             tcpreader.NewReaderStream(),
		tcp_return_channel: stream.tcp_return_channel,
		IPVersion: stream.IPVersion,
	}

	// We must read all the data from the reader or we will have the data standing in memory
	go dstream.processStream()

	return &dstream.reader
}

func tcpAssembler(tcpchannel chan tcpPacket, tcp_return_channel chan tcpData, done chan bool) {
	//TCP reassembly init
	streamFactoryV4 := &dnsStreamFactory{
		tcp_return_channel: tcp_return_channel,
		IPVersion: 6,
	}
	streamPoolV4 := tcpassembly.NewStreamPool(streamFactoryV4)
	assemblerV4 := tcpassembly.NewAssembler(streamPoolV4)

	streamFactoryV6 := &dnsStreamFactory{
		tcp_return_channel: tcp_return_channel,
		IPVersion: 6,
	}
	streamPoolV6 := tcpassembly.NewStreamPool(streamFactoryV6)
	assemblerV6 := tcpassembly.NewAssembler(streamPoolV6)
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-tcpchannel:
			{
				tcp := packet.packet.TransportLayer().(*layers.TCP)
				switch packet.IPVersion {
				case 4:
					assemblerV4.AssembleWithTimestamp(packet.packet.NetworkLayer().NetworkFlow(), tcp, packet.Timestamp)
					break
				case 6:
					assemblerV6.AssembleWithTimestamp(packet.packet.NetworkLayer().NetworkFlow(), tcp, packet.Timestamp)
					break
				}
			}
		case <-ticker:
			{
				// Every minute, flush connections that haven't seen activity in the past 2 minutes.
				assemblerV4.FlushOlderThan(time.Now().Add(time.Minute * -2))
			}
		}
	}
}

func packetDecoder(channel_input chan gopacket.Packet, tcp_channel []chan tcpPacket, tcp_return_channel <-chan tcpData, done chan bool, resultChannel chan<- DnsResult) {
	var SrcIP net.IP
	var DstIP net.IP
	var IPVersion uint8
	tcp_count := uint64(len(tcp_channel))
	for {
		select {
		case data := <-tcp_return_channel:
				msg := mkdns.Msg{}
				if err := msg.Unpack(data.data); err == nil {
					resultChannel <- DnsResult{time.Now(), msg, data.IPVersion, data.SrcIp, data.DstIp, "tcp", uint16(len(data.data))}
				}
		case packet := <-channel_input:
			{
				switch packet.NetworkLayer().LayerType() {
				case layers.LayerTypeIPv4:
					ip4 := packet.NetworkLayer().(*layers.IPv4)
					SrcIP = ip4.SrcIP
					DstIP = ip4.DstIP
					IPVersion = 4
				case layers.LayerTypeIPv6:
					ip6 := packet.NetworkLayer().(*layers.IPv6)
					SrcIP = ip6.SrcIP
					DstIP = ip6.DstIP
					IPVersion = 6
				default:
					break
				}

				switch packet.TransportLayer().LayerType() {
				case layers.LayerTypeUDP:
					msg := mkdns.Msg{}
					if err := msg.Unpack(packet.TransportLayer().LayerPayload()); err == nil {
						resultChannel <- DnsResult{time.Now(), msg, IPVersion, SrcIP, DstIP, "udp", uint16(len(packet.NetworkLayer().LayerPayload()))}
					}
				case layers.LayerTypeTCP:
					tcp_channel[packet.NetworkLayer().NetworkFlow().FastHash()%tcp_count] <- tcpPacket{
						IPVersion,
						packet,
						time.Now(),
					}
				}
			}
		case _ = <-done:
			break
		}
	}
}

func initialize(devName, filter string) *pcap.Handle {
	// Open device
	handle, err := pcap.OpenLive(devName, 65536, true, 10*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}

	// Set filter
	fmt.Fprintf(os.Stderr, "Using Device: %s\n", devName)
	fmt.Fprintf(os.Stderr, "Filter: %s\n", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	return handle
}

func handleInterrupt(done chan bool) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			fmt.Errorf("SIGINT")
			close(done)
			return
		}
	}()
}

func start(devName, filter string, resultChannel chan<- DnsResult, packetHandlerCount, packetChannelSize, tcpHandlerCount, tcpAssemblyChannelSize, tcpResultChannelSize uint, exiting chan bool) {
	var tcp_channel []chan tcpPacket
	handle := initialize(devName, filter)
	defer handle.Close()

	tcp_return_channel := make(chan tcpData, tcpResultChannelSize)
	processing_channel := make(chan gopacket.Packet, packetChannelSize)

	// Setup SIGINT handling
	handleInterrupt(exiting)

	for i := uint(0); i < tcpHandlerCount; i++ {
		tcp_channel = append(tcp_channel, make(chan tcpPacket, tcpAssemblyChannelSize))
		go tcpAssembler(tcp_channel[i], tcp_return_channel, exiting)
	}

	for i := uint(0); i < packetHandlerCount; i++ {
		go packetDecoder(processing_channel, tcp_channel, tcp_return_channel, exiting, resultChannel)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.NoCopy = true
	log.Println("Waiting for packets")
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				fmt.Println("PacketSource returned nil.")
				close(exiting)
				return
			}
			select {
			case processing_channel <- packet:
			default:
			}
		case <-exiting:
			return
		}
	}
}

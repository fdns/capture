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
	"io"
	"os"
	"os/signal"
)

type DnsHandler func(dns layers.DNS, SrcIP string, DstIP string, protocol string)
type DnsResult struct {
	timestamp    time.Time
	Dns          layers.DNS
	SrcIP        string
	DstIP        string
	Protocol     string
	PacketLength uint16
}

type tcpPacket struct {
	packet    gopacket.Packet
	Timestamp time.Time
}

type tcpData struct {
	data   []byte
	packet gopacket.Packet
	SrcIp  string
	DstIp  string
}

type dnsStreamFactory struct {
	tcp_return_channel chan tcpData
}

type dnsStream struct {
	Net, transport     gopacket.Flow
	reader             tcpreader.ReaderStream
	tcp_return_channel chan tcpData
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
						data:  result,
						SrcIp: ds.Net.Src().String(),
						DstIp: ds.Net.Dst().String(),
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
		transport:          transport,
		reader:             tcpreader.NewReaderStream(),
		tcp_return_channel: stream.tcp_return_channel,
	}

	// We must read all the data from the reader or we will have the data standing in memory
	go dstream.processStream()

	return &dstream.reader
}

func tcpAssembler(tcpchannel chan tcpPacket, tcp_return_channel chan tcpData, done chan bool) {
	//TCP reassembly init
	streamFactory := &dnsStreamFactory{
		tcp_return_channel: tcp_return_channel,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-tcpchannel:
			{
				tcp := packet.packet.TransportLayer().(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.packet.NetworkLayer().NetworkFlow(), tcp, packet.Timestamp)
			}
		case <-ticker:
			{
				// Every minute, flush connections that haven't seen activity in the past 2 minutes.
				assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
			}
		}
	}
}

func packetDecoder(channel_input chan gopacket.Packet, tcp_channel []chan tcpPacket, tcp_return_channel <-chan tcpData, done chan bool, resultChannel chan<- DnsResult) {
	var SrcIP string
	var DstIP string
	var dns layers.DNS
	var payload gopacket.Payload
	parser_dns_only := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, &dns, &payload)
	decodedLayers := []gopacket.LayerType{}
	tcp_count := uint64(len(tcp_channel))
	for {
		select {
		case data := <-tcp_return_channel:
			{
				parser_dns_only.DecodeLayers(data.data, &decodedLayers)
				for _, value := range decodedLayers {
					if value == layers.LayerTypeDNS {
						resultChannel <- DnsResult{time.Now(), dns, data.SrcIp, data.DstIp, "tcp", uint16(len(data.data))}
					}
				}
			}
		case packet := <-channel_input:
			{
				switch packet.NetworkLayer().LayerType() {
				case layers.LayerTypeIPv4:
					ip4 := packet.NetworkLayer().(*layers.IPv4)
					SrcIP = ip4.SrcIP.String()
					DstIP = ip4.DstIP.String()
				case layers.LayerTypeIPv6:
					ip6 := packet.NetworkLayer().(*layers.IPv6)
					SrcIP = ip6.SrcIP.String()
					DstIP = ip6.DstIP.String()
				default:
					break
				}

				switch packet.TransportLayer().LayerType() {
				case layers.LayerTypeUDP:
					if value := packet.Layer(layers.LayerTypeDNS); value != nil {
						resultChannel <- DnsResult{time.Now(), *value.(*layers.DNS), SrcIP, DstIP, "udp", uint16(len(packet.NetworkLayer().LayerPayload()))}
					}
				case layers.LayerTypeTCP:
					tcp_channel[packet.NetworkLayer().NetworkFlow().FastHash()%tcp_count] <- tcpPacket{
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

func initialize(devName string) *pcap.Handle {
	// Open device
	handle, err := pcap.OpenLive(devName, 65536, true, 10*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}

	// Set filter
	var filter string = "port 53"
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

func start(devName string, resultChannel chan<- DnsResult, packetHandlerCount, packetChannelSize, tcpHandlerCount uint, exiting chan bool) {
	var tcp_channel []chan tcpPacket
	handle := initialize(devName)
	defer handle.Close()

	tcp_return_channel := make(chan tcpData, 500)
	processing_channel := make(chan gopacket.Packet, packetChannelSize)

	// Setup SIGINT handling
	handleInterrupt(exiting)

	for i := uint(0); i < tcpHandlerCount; i++ {
		tcp_channel = append(tcp_channel, make(chan tcpPacket, 500))
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

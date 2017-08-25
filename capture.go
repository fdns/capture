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
			// Read until the End Of File, and use it as a signal to send the reassembed stream into the channel
			// Ensure the length of data is at least two to calculate the dns packet length
			if len(data) < 2 {
				return
			}
			// Parse the integer
			dns_data_len := int(binary.BigEndian.Uint16(data[:2]))

			// Check the parsed data is the expected size
			if len(data) < int(dns_data_len+2) {
				return
			}

			// Return the data to be processed
			ds.tcp_return_channel <- tcpData{
				data:  data[2 : dns_data_len+2],
				SrcIp: ds.Net.Src().String(),
				DstIp: ds.Net.Dst().String(),
			}
			return
		} else if err != nil {
			fmt.Errorf("Error when reading DNS buf", err)
		} else if count > 0 {
			// Append only if the last size was valid
			length := len(data)
			if length < 2 || length < int(binary.BigEndian.Uint16(data[:2]))+2 {
				data = append(data, tmp[0:count]...)
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

func packetDecoder(channel_input chan gopacket.Packet, tcp_channel chan tcpPacket, tcp_return_channel chan tcpData, done chan bool, dns_function DnsHandler) {
	var SrcIP string
	var DstIP string
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var udp layers.UDP
	var dns layers.DNS
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &udp, &dns, &payload)
	parser_dns_only := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, &dns, &payload)
	decodedLayers := []gopacket.LayerType{}
	for {

		select {
		case data := <-tcp_return_channel:
			{
				parser_dns_only.DecodeLayers(data.data, &decodedLayers)
				for _, value := range decodedLayers {
					if value == layers.LayerTypeDNS {
						dns_function(dns, data.SrcIp, data.DstIp, "tcp")
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
					parser.DecodeLayers(packet.Data(), &decodedLayers)
					for _, value := range decodedLayers {
						if value == layers.LayerTypeDNS {
							showDNS(dns, SrcIP, DstIP, "udp")
						}
					}
				case layers.LayerTypeTCP:
					tcp_channel <- tcpPacket{
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
	handle, err := pcap.OpenLive(devName, 65536, false, 500*time.Millisecond)
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

func start(devName string, dns_function DnsHandler) {
	handle := initialize(devName)
	defer handle.Close()

	tcp_channel := make(chan tcpPacket, 500)
	tcp_return_channel := make(chan tcpData, 500)
	processing_channel := make(chan gopacket.Packet, 500)
	done_channel := make(chan bool)

	// Setup SIGINT handling
	handleInterrupt(done_channel)

	// TODO: Launch more packet decoders
	go packetDecoder(processing_channel, tcp_channel, tcp_return_channel, done_channel, dns_function)
	go tcpAssembler(tcp_channel, tcp_return_channel, done_channel)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				fmt.Println("PacketSource returned nil.")
				close(done_channel)
				continue
			}
			processing_channel <- packet
		case _ = <-done_channel:
			return
		}
	}
}

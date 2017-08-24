package main

import (
	"fmt"
	"log"
	"time"

	"encoding/binary"
	"encoding/csv"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"os"
	"strconv"
)

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

func (ds *dnsStream) process_stream() {
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
			data = append(data, tmp[0:count]...)

			// Check that the size is valid
			length := len(data)
			if length > 2 {
				dns_data_len := int(binary.BigEndian.Uint16(data[:2]))
				if length > dns_data_len+2 {
					// Packet corrupted, there is more data from the declared
					return
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
	go dstream.process_stream()

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

func showDNS(dns layers.DNS, SrcIP string, DstIP string, protocol string) {
	for _, dnsQuestion := range dns.Questions {
		w := csv.NewWriter(os.Stdout)
		w.Write([]string{protocol, SrcIP, DstIP, strconv.FormatBool(dns.QR), strconv.Itoa(int(dns.OpCode)), strconv.Itoa(int(dns.ResponseCode)), strconv.Itoa(int(dns.ANCount)), string(dnsQuestion.Name)})
		w.Flush()
	}
	/*
		dnsANCount := int(dns.ANCount)

		fmt.Println("------------------------")
		fmt.Println("    DNS Record Detected")
		fmt.Println("    Protocol: ", protocol)

		for _, dnsQuestion := range dns.Questions {

			//t := time.Now()
			//timestamp := t.Format(time.RFC3339)
			fmt.Println("    DNS QR", string(strconv.FormatBool(dns.QR)))
			fmt.Println("    DNS OpCode: ", strconv.Itoa(int(dns.OpCode)))
			fmt.Println("    DNS ResponseCode: ", dns.ResponseCode.String())
			fmt.Println("    DNS # Answers: ", strconv.Itoa(dnsANCount))
			fmt.Println("    DNS Question: ", string(dnsQuestion.Name))
			fmt.Println("    DNS Endpoints: ", SrcIP, DstIP)

			if dnsANCount > 0 {

				for _, dnsAnswer := range dns.Answers {
					if dnsAnswer.IP.String() != "<nil>" {
						fmt.Println("    DNS Answer: ", dnsAnswer.IP.String())
					}
				}
			}
		}*/
}

func packetDecoder(channel_input chan gopacket.Packet, tcp_channel chan tcpPacket, tcp_return_channel chan tcpData, done chan bool) {
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
						showDNS(dns, data.SrcIp, data.DstIp, "tcp")
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
	fmt.Fprint(os.Stderr, "Using Device: \n", devName)
	fmt.Fprint(os.Stderr, "Filter: \n", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	return handle
}

func main() {
	// select a device to listen on
	//windows example
	//devName = "\\Device\\NPF_{9CA25EBF-B3D8-4FD0-90A6-070A16A7F2B4}"
	//linux example
	devName := "lo"
	//devName := "enp0s25"

	// Find all devices
	devices, devErr := pcap.FindAllDevs()
	if devErr != nil {
		log.Fatal(devErr)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		for _ = range device.Addresses {
			if device.Name == devName {
				break
			}
		}
	}

	handle := initialize(devName)
	defer handle.Close()

	tcp_channel := make(chan tcpPacket, 500)
	tcp_return_channel := make(chan tcpData, 500)
	processing_channel := make(chan gopacket.Packet, 500)
	done_channel := make(chan bool)
	// TODO: Launch more packet decoders
	go packetDecoder(processing_channel, tcp_channel, tcp_return_channel, done_channel)
	go tcpAssembler(tcp_channel, tcp_return_channel, done_channel)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	for packet := range packetSource.Packets() {
		if packet == nil {
			fmt.Println("PacketSource returned nil.")
			break
		}
		processing_channel <- packet
	}
}

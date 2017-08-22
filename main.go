package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strconv"
)

type DnsMsg struct {
	Timestamp       string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsOpCode       string
}

func parse_dns(dns layers.DNS, SrcIP string, DstIP string) {
	dnsOpCode := int(dns.OpCode)
	dnsResponseCode := int(dns.ResponseCode)
	dnsANCount := int(dns.ANCount)

	if (dns.QR == false) {
		for _, dnsQuestion := range dns.Questions {
			fmt.Println(string(dnsQuestion.Name))
		}
	}

	if (dns.QR == true && dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {

		fmt.Println("------------------------")
		fmt.Println("    DNS Record Detected")

		for _, dnsQuestion := range dns.Questions {

			t := time.Now()
			timestamp := t.Format(time.RFC3339)

			// Add a document to the index
			d := DnsMsg{Timestamp: timestamp, SourceIP: SrcIP,
				DestinationIP:   DstIP,
				DnsQuery:        string(dnsQuestion.Name),
				DnsOpCode:       strconv.Itoa(dnsOpCode),
				DnsResponseCode: strconv.Itoa(dnsResponseCode),
				NumberOfAnswers: strconv.Itoa(dnsANCount)}
			fmt.Println("    DNS OpCode: ", strconv.Itoa(int(dns.OpCode)))
			fmt.Println("    DNS ResponseCode: ", dns.ResponseCode.String())
			fmt.Println("    DNS # Answers: ", strconv.Itoa(dnsANCount))
			fmt.Println("    DNS Question: ", string(dnsQuestion.Name))
			fmt.Println("    DNS Endpoints: ", SrcIP, DstIP)

			if dnsANCount > 0 {

				for _, dnsAnswer := range dns.Answers {
					d.DnsAnswerTTL = append(d.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
					if dnsAnswer.IP.String() != "<nil>" {
						fmt.Println("    DNS Answer: ", dnsAnswer.IP.String())
						d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
					}
				}
			}
		}
	}
}

func packet_decoder(channel chan []byte, done chan bool) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS
	var SrcIP string
	var DstIP string
	var netFlow gopacket.Flow
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)
	decodedLayers := []gopacket.LayerType{}
	for {

		select {
			case packet := <-channel:
				{
					err := parser.DecodeLayers(packet, &decodedLayers)
					for _, typ := range decodedLayers {
						switch typ {
						case layers.LayerTypeIPv4:
							SrcIP = ip4.SrcIP.String()
							DstIP = ip4.DstIP.String()
							netFlow = ip4.NetworkFlow()
						case layers.LayerTypeIPv6:
							SrcIP = ip6.SrcIP.String()
							DstIP = ip6.DstIP.String()
							netFlow = ip6.NetworkFlow()
						case layers.LayerTypeTCP:
							break
						case layers.LayerTypeDNS:
							parse_dns(dns, SrcIP, DstIP)
						}
					}

					if err != nil {
						fmt.Println("  Error encountered:", err)
					}
				}
			case _ = <-done:
				break
		}
	}
}

func initialize(devName string) *pcap.Handle {
	// Open device
	handle, err := pcap.OpenLive(devName, 65536, false, 500 * time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}

	// Set filter
	var filter string = "udp and port 53"
	fmt.Println()
	fmt.Println("Using Device: ", devName)
	fmt.Println("Filter: ", filter)
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

	// Find all devices
	devices, devErr := pcap.FindAllDevs()
	if devErr != nil {
		log.Fatal(devErr)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
			if device.Name == devName {
				break
			}
		}
	}

	handle := initialize(devName)
	defer handle.Close()

	proc_channel := make(chan []byte, 500)
	done_channel := make(chan bool)
	go packet_decoder(proc_channel, done_channel)

	count := 0
	for {
		data, _, err := handle.ReadPacketData()
		count++
		if err != nil {
			fmt.Println("Error reading packet data: ", err)
			continue
		}
		proc_channel <- data
		if count % 1000 == 0 {
			fmt.Print("Count ")
			fmt.Println(count)
		}
	}
}

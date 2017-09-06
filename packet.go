package main

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/ip4defrag"
	mkdns "github.com/miekg/dns"
	"net"
	"fmt"
)

type PacketEncoder struct {
	input <-chan gopacket.Packet
	ip4Defrgger chan<- layers.IPv4
	ip4DefrggerReturn <-chan layers.IPv4
	tcpAssembly []chan tcpPacket
	tcpReturnChannel <-chan tcpData
	resultChannel chan<- DnsResult
	done chan bool
}

func ipv4Defragger(ipInput <-chan layers.IPv4, ipOut chan layers.IPv4, done chan bool) {
	var ip layers.IPv4
	ipv4Defragger := ip4defrag.NewIPv4Defragmenter()
	tiker := time.NewTicker(1 * time.Minute)
	for {
		select {
		case ip = <-ipInput:
			result, err := ipv4Defragger.DefragIPv4(&ip)
			if err == nil && result != nil {
				ipOut <- *result
			}
		case <-tiker.C:
			ipv4Defragger.DiscardOlderThan(time.Now().Add(time.Minute * -1))
		case <-done:
			tiker.Stop()
			return
		}
	}
}

func (encoder *PacketEncoder) processTransport(foundLayerTypes *[]gopacket.LayerType, udp *layers.UDP, tcp *layers.TCP, flow *gopacket.Flow, IPVersion uint8, SrcIP, DstIP net.IP) {
	for _, layerType := range *foundLayerTypes {
		switch layerType {
		case layers.LayerTypeUDP:
			if udp.DstPort == 53 || udp.SrcPort == 53 {
				msg := mkdns.Msg{}
				if err := msg.Unpack(udp.Payload); err == nil {
					encoder.resultChannel <- DnsResult{time.Now(), msg, IPVersion, SrcIP, DstIP, "udp", uint16(len(udp.Payload))}
				}
			}
		case layers.LayerTypeTCP:
			/*
			if tcp.SrcPort == 53 || tcp.DstPort == 53 {
				encoder.tcpAssembly[flow.FastHash()%tcpChannelCount] <- tcpPacket{
					IPVersion,
					packet,
					time.Now(),
				}
			}*/
		}
	}

}

func (encoder *PacketEncoder) run() {
	var SrcIP net.IP
	var DstIP net.IP
	var IPVersion uint8
	var ethLayer layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var udp layers.UDP
	var tcp layers.TCP
	var flow gopacket.Flow

	tcpChannelCount := uint64(len(encoder.tcpAssembly))
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ip4,
		&ip6,
		&udp,
		&tcp,
	)
	parserOnlyUDP := gopacket.NewDecodingLayerParser(
		layers.LayerTypeUDP,
		&udp,
	)
	parserOnlyTCP := gopacket.NewDecodingLayerParser(
		layers.LayerTypeTCP,
		&tcp,
	)
	foundLayerTypes := []gopacket.LayerType{}
	for {
		select {
		case data := <-encoder.tcpReturnChannel:
			msg := mkdns.Msg{}
			if err := msg.Unpack(data.data); err == nil {
				encoder.resultChannel <- DnsResult{time.Now(), msg, data.IPVersion, data.SrcIp, data.DstIp, "tcp", uint16(len(data.data))}
			}
		case ip4 = <- encoder.ip4DefrggerReturn:
			// Packet was defragged, parse the remaining data
			if ip4.Protocol == layers.IPProtocolUDP {
				parserOnlyUDP.DecodeLayers(ip4.Payload, &foundLayerTypes)
			} else if ip4.Protocol == layers.IPProtocolTCP {
				parserOnlyTCP.DecodeLayers(ip4.Payload, &foundLayerTypes)
			} else {
				// Protocol not supported
				break
			}
		case packet := <-encoder.input:
			{
				_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)
				// Reiterate when reassembling the packet in case of fragmentation
				for {
					// first parse the ip layer, so we can find fragmented packets
					for _, layerType := range foundLayerTypes {
						switch layerType {
						case layers.LayerTypeIPv4:
							// Check for fragmentation
							if ip4.Flags & layers.IPv4DontFragment == 0 && (ip4.Flags & layers.IPv4MoreFragments != 0 || ip4.FragOffset != 0) {
								// Packet is fragmented, send it to the defragger
								fmt.Println("Defragging")
								encoder.ip4Defrgger <- ip4
								break
							}
							// Store the packet metadata
							SrcIP = ip4.SrcIP
							DstIP = ip4.DstIP
							IPVersion = 4
							flow = ip4.NetworkFlow()
							//processTransport(foundLayerTypes *[]gopacket.LayerType, udp, tcp, flow, IPVersion, SrcIP, DstIP)
						case layers.LayerTypeIPv6:
							// Store the packet metadata
							SrcIP = ip6.SrcIP
							DstIP = ip6.DstIP
							IPVersion = 6
							flow = ip6.NetworkFlow()
						case layers.LayerTypeUDP:
							if udp.DstPort == 53 || udp.SrcPort == 53 {
								msg := mkdns.Msg{}
								if err := msg.Unpack(udp.Payload); err == nil {
									encoder.resultChannel <- DnsResult{time.Now(), msg, IPVersion, SrcIP, DstIP, "udp", uint16(len(udp.Payload))}
								}
							}
						case layers.LayerTypeTCP:
							if tcp.SrcPort == 53 || tcp.DstPort == 53 {
								encoder.tcpAssembly[flow.FastHash()%tcpChannelCount] <- tcpPacket{
									IPVersion,
									packet,
									time.Now(),
								}
							}
						}
					}
					break
				}
			}
		case <-encoder.done:
			break
		}
	}
}

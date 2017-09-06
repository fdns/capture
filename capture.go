package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	mkdns "github.com/miekg/dns"
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
	ip4DefraggerChannel := make(chan layers.IPv4, 500)

	// Setup SIGINT handling
	handleInterrupt(exiting)

	for i := uint(0); i < tcpHandlerCount; i++ {
		tcp_channel = append(tcp_channel, make(chan tcpPacket, tcpAssemblyChannelSize))
		go tcpAssembler(tcp_channel[i], tcp_return_channel, exiting)
	}

	encoder := PacketEncoder{
		processing_channel,
		ip4DefraggerChannel,
		nil,
		tcp_channel,
		tcp_return_channel,
		resultChannel,
		exiting,
	}
	
	for i := uint(0); i < packetHandlerCount; i++ {
		go encoder.run()
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

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	mkdns "github.com/miekg/dns"
	"net"
	"os"
	"os/signal"
)

type CaptureOptions struct {
	devName                       string
	filter                        string
	port                          uint16
	resultChannel                 chan<- DnsResult
	packetHandlerCount            uint
	packetChannelSize             uint
	tcpHandlerCount               uint
	tcpAssemblyChannelSize        uint
	tcpResultChannelSize          uint
	ip4DefraggerChannelSize       uint
	ip4DefraggerReturnChannelSize uint
	exiting                       chan bool
}

type DnsCapturer struct {
	options CaptureOptions
}

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

func NewDnsCapturer(options CaptureOptions) DnsCapturer {
	return DnsCapturer{options}
}

func (capturer *DnsCapturer) Start() {
	var tcp_channel []chan tcpPacket
	options := capturer.options
	handle := initialize(options.devName, options.filter)
	defer handle.Close()

	tcp_return_channel := make(chan tcpData, options.tcpResultChannelSize)
	processing_channel := make(chan gopacket.Packet, options.packetChannelSize)
	ip4DefraggerChannel := make(chan layers.IPv4, options.ip4DefraggerChannelSize)
	ip4DefraggerReturn := make(chan layers.IPv4, options.ip4DefraggerReturnChannelSize)

	// Setup SIGINT handling
	handleInterrupt(options.exiting)

	for i := uint(0); i < options.tcpHandlerCount; i++ {
		tcp_channel = append(tcp_channel, make(chan tcpPacket, options.tcpAssemblyChannelSize))
		go tcpAssembler(tcp_channel[i], tcp_return_channel, options.exiting)
	}

	go ipv4Defragger(ip4DefraggerChannel, ip4DefraggerReturn, options.exiting)

	encoder := PacketEncoder{
		options.port,
		processing_channel,
		ip4DefraggerChannel,
		ip4DefraggerReturn,
		tcp_channel,
		tcp_return_channel,
		options.resultChannel,
		options.exiting,
	}

	for i := uint(0); i < options.packetHandlerCount; i++ {
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
				close(options.exiting)
				return
			}
			select {
			case processing_channel <- packet:
			default:
			}
		case <-options.exiting:
			return
		}
	}
}

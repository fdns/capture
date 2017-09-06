package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"net"
	"time"
)

type tcpPacket struct {
	IPVersion uint8
	tcp       layers.TCP
	Timestamp time.Time
	flow      gopacket.Flow
}

type tcpData struct {
	IPVersion uint8
	data      []byte
	SrcIp     net.IP
	DstIp     net.IP
}

type dnsStreamFactory struct {
	tcp_return_channel chan tcpData
	IPVersion          uint8
}

type dnsStream struct {
	Net                gopacket.Flow
	reader             tcpreader.ReaderStream
	tcp_return_channel chan tcpData
	IPVersion          uint8
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
				if curLength >= expected {
					result := data[2:expected]

					// Send the data to be processed
					ds.tcp_return_channel <- tcpData{
						IPVersion: ds.IPVersion,
						data:      result,
						SrcIp:     net.IP(ds.Net.Src().Raw()),
						DstIp:     net.IP(ds.Net.Dst().Raw()),
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
		IPVersion:          stream.IPVersion,
	}

	// We must read all the data from the reader or we will have the data standing in memory
	go dstream.processStream()

	return &dstream.reader
}

func tcpAssembler(tcpchannel chan tcpPacket, tcp_return_channel chan tcpData, done chan bool) {
	//TCP reassembly init
	streamFactoryV4 := &dnsStreamFactory{
		tcp_return_channel: tcp_return_channel,
		IPVersion:          6,
	}
	streamPoolV4 := tcpassembly.NewStreamPool(streamFactoryV4)
	assemblerV4 := tcpassembly.NewAssembler(streamPoolV4)

	streamFactoryV6 := &dnsStreamFactory{
		tcp_return_channel: tcp_return_channel,
		IPVersion:          6,
	}
	streamPoolV6 := tcpassembly.NewStreamPool(streamFactoryV6)
	assemblerV6 := tcpassembly.NewAssembler(streamPoolV6)
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-tcpchannel:
			{
				switch packet.IPVersion {
				case 4:
					assemblerV4.AssembleWithTimestamp(packet.flow, &packet.tcp, packet.Timestamp)
					break
				case 6:
					assemblerV6.AssembleWithTimestamp(packet.flow, &packet.tcp, packet.Timestamp)
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

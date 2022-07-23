package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	device            = "eth0"
	snapshotLen int32 = 1024
	promiscuous       = false
	err         error
	timeout     = 30 * time.Second
	handle      *pcap.Handle
	packetcount = 0
)

func printInfo(packet gopacket.Packet) {
	//Check if packet is SIP packet
	sipLayer := packet.Layer(layers.LayerTypeSIP)
	if sipLayer != nil {
		fmt.Println("Probable VoIP detected")
		sipPacket, _ := sipLayer.(*layers.SIP)
		fmt.Println(sipPacket.GetAllHeaders())
		fmt.Println(sipPacket.GetAuthorization())
		fmt.Println(sipPacket.GetCSeq())
		fmt.Println(sipPacket.GetUserAgent())
	}
}

func main() {
	//Open output pcap file and write header
	f, _ := os.Create("capture.pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
	defer f.Close()

	//Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//Use handle as packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//p:=packet.Layer(layers.LayerTypeSIP)
		printInfo(packet)
		//w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		packetcount++
		//Capturing 100 packets
		if packetcount > 100 {
			break
		}
	}
}

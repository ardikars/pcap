package pcap.sample;

import pcap.api.Bootstrap;
import pcap.api.Pcap;
import pcap.codec.DataLinkLayer;
import pcap.codec.NetworkLayer;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.codec.arp.Arp;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.ethernet.Vlan;
import pcap.codec.icmp.Icmp4;
import pcap.codec.icmp.Icmp6;
import pcap.codec.ip.Ip4;
import pcap.codec.ip.Ip6;
import pcap.codec.ip.ip6.*;
import pcap.codec.tcp.Tcp;
import pcap.codec.udp.Udp;
import pcap.common.memory.Memories;
import pcap.common.memory.Memory;
import pcap.spi.Dumper;

import java.util.stream.StreamSupport;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class LoopSample {

//    public static void main(String[] args) throws Exception {
//        Pcap pcap = Bootstrap.bootstrap()
//                .open();
//        pcap.setFilter("arp", true);
////        Dumper dumper = pcap.dumpOpen("/tmp/aw.pcap");
//        pcap.loop(50, (handler, header, buffer) -> {
////            handler.dump(header, buffer);
//            Memory memory = Memories.wrap(buffer.buffer());
//            memory.writerIndex(memory.capacity());
//            Ethernet.newPacket(memory)
//                    .forEach(System.out::println);
//            memory.release();
//        }, null);
//        pcap.close();
//    }

    public static void main(String[] args) throws Exception {
        Pcap pcap = Bootstrap.bootstrap()
                .open();
        pcap.setFilter("ip", true);
        pcap.loop(100, (args1, header, buffer) -> {
            Memory memory = Memories.wrap(buffer.buffer());
            memory.writerIndex(memory.capacity());
            Packet packet = Ethernet.newPacket(memory);
            StreamSupport.stream(packet.spliterator(), false)
//                    .filter(pkt -> pkt instanceof Ip6)
                    .forEach(System.out::println);
        }, null);
    }

    static {
        DataLinkLayer.register(new DataLinkLayer(0x1, "Ethernet"), new Ethernet.Builder());

        NetworkLayer.register(new NetworkLayer(0x8100, "IEEE 802.1Q VLAN-tagged frames"), new Vlan.Builder());
        NetworkLayer.register(new NetworkLayer(0x88a8, "QinQ"), new Vlan.Builder());
        NetworkLayer.register(new NetworkLayer(0x0806, "Arp"), new Arp.Builder());
        NetworkLayer.register(new NetworkLayer(0x0800, "IPv4"), new Ip4.Builder());
        NetworkLayer.register(new NetworkLayer(0x86dd, "IPv6"), new Ip6.Builder());

        TransportLayer.register(new TransportLayer(6, "Transmission Control Protocol"), new Tcp.Builder());
        TransportLayer.register(new TransportLayer(17, "User Datagram Protocol"), new Udp.Builder());
        TransportLayer.register(new TransportLayer(1, "Internet Control Message Protocol Version 4"), new Icmp4.Builder());
        TransportLayer.register(new TransportLayer(58, "Internet Control Message Protocol Version 6"), new Icmp6.Builder());
    }

}

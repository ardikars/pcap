package pcap.sample;

import pcap.api.Pcap;
import pcap.api.PcapLive;
import pcap.api.Pcaps;
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
import pcap.codec.tcp.Tcp;
import pcap.codec.udp.Udp;
import pcap.common.memory.Memories;
import pcap.common.memory.Memory;
import pcap.common.net.Inet4Address;
import pcap.common.net.MacAddress;
import pcap.spi.exception.ErrorException;

import java.nio.ByteBuffer;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
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
    //    Pcap pcap = Pcaps.live(new PcapLive(Pcaps.lookupInterface()));
    //    pcap.setFilter("ip6", true);
    //    pcap.loop(2000, (args1, header, buffer) -> {
    //      Memory memory = Memories.wrap(buffer.buffer());
    //      memory.writerIndex(memory.capacity());
    //      Ethernet ethernet = Ethernet.newPacket(memory);
    //      ethernet.forEach(System.out::println);
    //    }, pcap);
    //    pcap.close();
    reply();
  }

  public static void reply() throws Exception {
    Pcap pcap = Pcaps.live(new PcapLive(Pcaps.lookupInterface()));
    pcap.setFilter("arp", true);
    pcap.loop(
        2,
        (args, header, buffer) -> {
          Memory memory = Memories.wrap(buffer.buffer());
          memory.writerIndex(memory.capacity());
          Packet packet = Ethernet.newPacket(memory);
          Arp arp = packet.get(Arp.class).get(0);
          arp.getHeader().getBuilder()
                .targetHardwareAddress(MacAddress.DUMMY)
                .targetProtocolAddress(Inet4Address.valueOf("10.14.204.11"))
                .reset();
          ByteBuffer buf = arp.getHeader().getBuffer().nioBuffer();
          Memory memBuf = Memories.wrap(buf);
            System.out.println(memBuf.memoryAddress());
          memBuf.setIndex(0, memBuf.capacity());
          Packet pkt = Ethernet.newPacket(memBuf);
          Arp arp2 = pkt.get(Arp.class).get(0);
            System.out.println(arp);
            System.out.println("%%%%");
            System.out.println(arp2);
          try {
            args.send(buf);
            System.out.println("Send");
          } catch (ErrorException e) {
            System.out.println(e);
          }
        },
        pcap);
    pcap.close();
  }

  static {
    DataLinkLayer.register(new DataLinkLayer(0x1, "Ethernet"), new Ethernet.Builder());

    NetworkLayer.register(
        new NetworkLayer(0x8100, "IEEE 802.1Q VLAN-tagged frames"), new Vlan.Builder());
    NetworkLayer.register(new NetworkLayer(0x88a8, "QinQ"), new Vlan.Builder());
    NetworkLayer.register(new NetworkLayer(0x0806, "Arp"), new Arp.Builder());
    NetworkLayer.register(new NetworkLayer(0x0800, "IPv4"), new Ip4.Builder());
    NetworkLayer.register(new NetworkLayer(0x86dd, "IPv6"), new Ip6.Builder());

    TransportLayer.register(
        new TransportLayer(6, "Transmission Control Protocol"), new Tcp.Builder());
    TransportLayer.register(new TransportLayer(17, "User Datagram Protocol"), new Udp.Builder());
    TransportLayer.register(
        new TransportLayer(1, "Internet Control Message Protocol Version 4"), new Icmp4.Builder());
    TransportLayer.register(
        new TransportLayer(58, "Internet Control Message Protocol Version 6"), new Icmp6.Builder());
  }
}

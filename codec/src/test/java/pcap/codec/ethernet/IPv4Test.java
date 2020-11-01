package pcap.codec.ethernet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.ip.IPv4;
import pcap.common.net.InetAddresses;
import pcap.spi.PacketBuffer;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.option.DefaultOfflineOptions;

@RunWith(JUnitPlatform.class)
public class IPv4Test {

  @Test
  void readWrite() throws ErrorException, BreakException {
    try (final Pcap pcap =
        Service.Creator.create("PcapService")
            .offline("../jdk7/src/test/resources/sample.pcapng", new DefaultOfflineOptions())) {

      final PacketBuffer buffer = pcap.allocate(PacketBuffer.class).capacity(24);
      buffer.writerIndex(buffer.capacity());
      buffer.setByte(0, (4 & 0xF) << 4 | 6 & 0xF);

      IPv4 ipv4 = buffer.cast(IPv4.class);

      // write
      ipv4.version(4);
      ipv4.ihl(5);
      ipv4.dscp(2);
      ipv4.ecn(3);
      ipv4.totalLength(128);
      ipv4.identification(1);
      ipv4.flags(2);
      ipv4.fragmentOffset(0);
      ipv4.ttl(64);
      ipv4.protocol(6);
      ipv4.source(InetAddresses.fromBytesToInet4Address(new byte[] {10, 0, 0, 1}));
      ipv4.destination(InetAddresses.fromBytesToInet4Address(new byte[] {10, 0, 0, 2}));
      ipv4.checksum(ipv4.calculateChecksum());

      // read
      Assertions.assertEquals(4, ipv4.version());
      Assertions.assertEquals(5, ipv4.ihl());
      Assertions.assertEquals(3, ipv4.ecn());
      Assertions.assertEquals(128, ipv4.totalLength());
      Assertions.assertEquals(2, ipv4.flags());
      Assertions.assertEquals(64, ipv4.ttl());
      Assertions.assertEquals(6, ipv4.protocol());
      Assertions.assertEquals(ipv4.calculateChecksum(), ipv4.checksum());
      Assertions.assertArrayEquals(new byte[] {10, 0, 0, 1}, ipv4.source().getAddress());
      Assertions.assertArrayEquals(new byte[] {10, 0, 0, 2}, ipv4.destination().getAddress());
      Assertions.assertArrayEquals(new byte[0], ipv4.options());

      ipv4.ihl(6);
      ipv4.options(new byte[] {1, 1, 1, 1});
      Assertions.assertArrayEquals(new byte[] {1, 1, 1, 1}, ipv4.options());

      // to string
      Assertions.assertNotNull(ipv4.toString());

      Assertions.assertThrows(
          IllegalStateException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              buffer.setIndex(buffer.capacity(), buffer.capacity()).cast(IPv4.class);
            }
          });

      // release
      buffer.release();
    }
  }
}

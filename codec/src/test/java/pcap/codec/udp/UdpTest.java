package pcap.codec.udp;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.net.InetAddresses;
import pcap.common.util.Hexs;
import pcap.spi.PacketBuffer;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

import java.net.Inet4Address;

@RunWith(JUnitPlatform.class)
public class UdpTest {

  private static final byte[] BYTES =
      Hexs.parseHex(
          "bcd90035003f03b35d6801000001000000000001076d6f7a696c6c610e636c6f7564666c6172652d646e7303636f6d00000100010000290200000000000000");

  @Test
  void readWrite()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Service service = Service.Creator.create("PcapService");
    try (final Pcap pcap = service.live(service.interfaces(), new DefaultLiveOptions())) {
      final PacketBuffer buffer =
          pcap.allocate(PacketBuffer.class)
              .capacity(BYTES.length)
              .byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN);
      buffer.writeBytes(BYTES);
      final Udp udp = buffer.cast(Udp.class);

      Assertions.assertEquals(48345, udp.sourcePort());
      Assertions.assertEquals(53, udp.destinationPort());
      Assertions.assertEquals(63, udp.length());
      Assertions.assertEquals(947, udp.checksum());

      Inet4Address src = InetAddresses.fromBytesToInet4Address(new byte[]{(byte) 192, (byte) 168, 18, 20});
      Inet4Address dst = InetAddresses.fromBytesToInet4Address(new byte[]{(byte) 192, (byte) 168, 18, 1});
      Assertions.assertTrue(udp.isValidChecksum(src, dst, udp.length() - udp.size()));

      udp.sourcePort(53);
      udp.destinationPort(48345);
      udp.length(64);
      udp.checksum(0);

      Assertions.assertEquals(53, udp.sourcePort());
      Assertions.assertEquals(48345, udp.destinationPort());
      Assertions.assertEquals(64, udp.length());
      Assertions.assertEquals(0, udp.checksum());

      buffer.release();
    }
  }
}

/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.codec.ethernet.Ethernet;
import pcap.codec.udp.Udp;
import pcap.common.util.Hexs;
import pcap.spi.PacketBuffer;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.ActivatedException;
import pcap.spi.exception.error.InterfaceNotSupportTimestampTypeException;
import pcap.spi.exception.error.InterfaceNotUpException;
import pcap.spi.exception.error.NoSuchDeviceException;
import pcap.spi.exception.error.PermissionDeniedException;
import pcap.spi.exception.error.PromiscuousModePermissionDeniedException;
import pcap.spi.exception.error.RadioFrequencyModeNotSupportedException;
import pcap.spi.exception.error.TimestampPrecisionNotSupportedException;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
class AbstractPacketTest {

  private static final byte[] ETHERNET = Hexs.parseHex("d80d17269cee8c8590c30b330800");
  private static final byte[] ETHERNET2 = Hexs.parseHex("d90d17269cee8c8590c30b330800");

  @Test
  void equalsAndHasCodeTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Service service = Service.Creator.create("PcapService");
    try (final Pcap pcap = service.live(service.interfaces(), new DefaultLiveOptions())) {
      final PacketBuffer ethernetBuffer =
          pcap.allocate(PacketBuffer.class)
              .capacity(ETHERNET.length)
              .byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN);
      final PacketBuffer ethernet2Buffer =
          pcap.allocate(PacketBuffer.class)
              .capacity(ETHERNET2.length)
              .byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN);

      ethernetBuffer.writeBytes(ETHERNET);
      ethernet2Buffer.writeBytes(ETHERNET2);

      Ethernet ethernet = Ethernet.newInstance(ETHERNET.length, ethernetBuffer);
      Ethernet ethernet2 = Ethernet.newInstance(ETHERNET2.length, ethernet2Buffer);
      Udp udp = Udp.newInstance(8, ethernetBuffer);

      Assertions.assertNotEquals(udp, new LinkedList<String>());
      Assertions.assertNotEquals(udp, ethernet);
      Assertions.assertNotEquals(ETHERNET, ethernet);
      Assertions.assertNotEquals(ethernet, ethernet2);
      Assertions.assertEquals(ethernet, ethernet);
      Assertions.assertTrue(ethernet.hashCode() >= 0 || ethernet.hashCode() <= 0);

      ethernetBuffer.release();
      ethernet2Buffer.release();
    }
  }

  @Test
  void calculate()
      throws UnknownHostException, ErrorException, PermissionDeniedException,
          PromiscuousModePermissionDeniedException, TimestampPrecisionNotSupportedException,
          RadioFrequencyModeNotSupportedException, NoSuchDeviceException, ActivatedException,
          InterfaceNotUpException, InterfaceNotSupportTimestampTypeException {
    InetAddress dstIp4 = Inet4Address.getByName("127.0.0.1");
    InetAddress srcIp4 = Inet4Address.getByName("127.0.0.1");
    InetAddress dstIp6 = Inet4Address.getByName("::1");
    InetAddress srcIp6 = Inet4Address.getByName("::1");

    Service service = Service.Creator.create("PcapService");
    try (final Pcap pcap = service.live(service.interfaces(), new DefaultLiveOptions())) {
      PacketBuffer buffer = pcap.allocate(PacketBuffer.class).capacity(40);
      AbstractPacket.Checksum.calculate(buffer, 0, dstIp4, srcIp4, 0, 0, 0);
      AbstractPacket.Checksum.calculate(buffer, 0, dstIp6, srcIp6, 0, 0, 0);
      AbstractPacket.Checksum.calculate(buffer, 0, dstIp6, srcIp4, 0, 0, 0);
      AbstractPacket.Checksum.calculate(buffer, 0, dstIp4, srcIp6, 0, 0, 0);
      Assertions.assertTrue(buffer.release());
    }
  }
}

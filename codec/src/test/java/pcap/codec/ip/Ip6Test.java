/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ip;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
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

@RunWith(JUnitPlatform.class)
public class Ip6Test {

  private static final byte[] BYTES =
      Hexs.parseHex(
          "60000000004706382607f8b0400c0c03000000000000001a20010470e5bfdead49572174e82c48870019f9c79563979d03a0883150180150e6870000323230206d782e676f6f676c652e636f6d2045534d5450206d313773693130353135393376636b2e32202d2067736d74700d0a");

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

      final Ip6 ip6 = buffer.cast(Ip6.class);
      final Ip6 comparison = Ip6.newInstance(40, buffer);
      Assertions.assertEquals(ip6, comparison);

      Assertions.assertEquals(6, ip6.version());
      Assertions.assertEquals(0, ip6.trafficClass());
      Assertions.assertEquals(0, ip6.flowLabel());
      Assertions.assertEquals(71, ip6.payloadLength());
      Assertions.assertEquals(6, ip6.nextHeader());
      Assertions.assertEquals(56, ip6.hopLimit());
      Assertions.assertArrayEquals(
          InetAddresses.fromBytesToInet6Address(Hexs.parseHex("2607f8b0400c0c03000000000000001a"))
              .getAddress(),
          ip6.source().getAddress());
      Assertions.assertArrayEquals(
          InetAddresses.fromBytesToInet6Address(Hexs.parseHex("20010470e5bfdead49572174e82c4887"))
              .getAddress(),
          ip6.destination().getAddress());

      ip6.version(1);
      ip6.trafficClass(2);
      ip6.flowLabel(3);
      ip6.payloadLength(70);
      ip6.nextHeader(17);
      ip6.hopLimit(64);
      ip6.source(
          InetAddresses.fromBytesToInet6Address(Hexs.parseHex("2607f8b0400c0c03000000000000001b")));
      ip6.destination(
          InetAddresses.fromBytesToInet6Address(Hexs.parseHex("20010470e5bfdead49572174e82c4888")));

      Assertions.assertEquals(1, ip6.version());
      Assertions.assertEquals(2, ip6.trafficClass());
      Assertions.assertEquals(3, ip6.flowLabel());
      Assertions.assertEquals(70, ip6.payloadLength());
      Assertions.assertEquals(17, ip6.nextHeader());
      Assertions.assertEquals(64, ip6.hopLimit());
      Assertions.assertArrayEquals(
          InetAddresses.fromBytesToInet6Address(Hexs.parseHex("2607f8b0400c0c03000000000000001b"))
              .getAddress(),
          ip6.source().getAddress());
      Assertions.assertArrayEquals(
          InetAddresses.fromBytesToInet6Address(Hexs.parseHex("20010470e5bfdead49572174e82c4888"))
              .getAddress(),
          ip6.destination().getAddress());

      Assertions.assertNotNull(ip6.toString());

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Ip6.newInstance(0, buffer);
            }
          });

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Ip6.newInstance(40, buffer.setIndex(0, 0));
            }
          });

      buffer.release();
    }
  }
}

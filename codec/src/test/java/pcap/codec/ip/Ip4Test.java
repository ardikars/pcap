/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ip;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import pcap.codec.ethernet.Ethernet;
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

class Ip4Test {

  private static final byte[] BYTES = Hexs.parseHex("4500005b00004000400666acc0a8006d4a7dc85e");

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

      final Ip4 ipv4 = buffer.cast(Ip4.class);
      final Ip4 comparison = Ip4.newInstance(ipv4.size(), buffer);
      Assertions.assertEquals(ipv4, comparison);
      Assertions.assertEquals(ipv4.hashCode(), comparison.hashCode());

      Assertions.assertEquals(4, ipv4.version());
      Assertions.assertEquals(5, ipv4.ihl());
      Assertions.assertEquals(0, ipv4.dscp());
      Assertions.assertEquals(0, ipv4.ecn());
      Assertions.assertEquals(91, ipv4.totalLength());
      Assertions.assertEquals(0, ipv4.identification());
      Assertions.assertEquals(2, ipv4.flags());
      Assertions.assertEquals(0, ipv4.fragmentOffset());
      Assertions.assertEquals(64, ipv4.ttl());
      Assertions.assertEquals(6, ipv4.protocol());
      Assertions.assertEquals(26284, ipv4.checksum());
      Assertions.assertTrue(ipv4.isValidChecksum());
      Assertions.assertEquals("192.168.0.109", ipv4.source().getHostAddress());
      Assertions.assertEquals("74.125.200.94", ipv4.destination().getHostAddress());
      Assertions.assertArrayEquals(new byte[0], ipv4.options());
      Assertions.assertEquals(ipv4.ihl() * 4, ipv4.size());

      final PacketBuffer newBuffer =
          pcap.allocate(PacketBuffer.class)
              .capacity(BYTES.length + 4)
              .byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN);
      newBuffer.writerIndex(newBuffer.capacity());

      newBuffer.setByte(0, (4 & 0xF) << 4 | 6 & 0xF);

      final Ip4 newIpv4 = newBuffer.cast(Ip4.class);
      newIpv4.version(5);
      newIpv4.ihl(6);
      newIpv4.dscp(ipv4.dscp());
      newIpv4.ecn(ipv4.ecn());
      newIpv4.totalLength(ipv4.totalLength());
      newIpv4.identification(ipv4.identification());
      newIpv4.flags(ipv4.flags());
      newIpv4.fragmentOffset(ipv4.fragmentOffset());
      newIpv4.ttl(ipv4.ttl());
      newIpv4.protocol(ipv4.protocol());
      newIpv4.source(ipv4.source());
      newIpv4.destination(ipv4.destination());
      newIpv4.options(new byte[] {127, 0, 0, 1});
      newIpv4.checksum(newIpv4.calculateChecksum());

      Assertions.assertEquals(5, newIpv4.version());
      Assertions.assertEquals(6, newIpv4.ihl());
      Assertions.assertEquals(ipv4.dscp(), newIpv4.dscp());
      Assertions.assertEquals(ipv4.ecn(), newIpv4.ecn());
      Assertions.assertEquals(ipv4.totalLength(), newIpv4.totalLength());
      Assertions.assertEquals(ipv4.identification(), newIpv4.identification());
      Assertions.assertEquals(ipv4.flags(), newIpv4.flags());
      Assertions.assertEquals(ipv4.fragmentOffset(), newIpv4.fragmentOffset());
      Assertions.assertEquals(ipv4.ttl(), newIpv4.ttl());
      Assertions.assertEquals(ipv4.protocol(), newIpv4.protocol());
      Assertions.assertNotEquals(ipv4.checksum(), newIpv4.checksum());
      Assertions.assertTrue(newIpv4.isValidChecksum());
      Assertions.assertEquals(ipv4.source().getHostAddress(), newIpv4.source().getHostAddress());
      Assertions.assertEquals(
          ipv4.destination().getHostAddress(), newIpv4.destination().getHostAddress());
      Assertions.assertArrayEquals(new byte[] {127, 0, 0, 1}, newIpv4.options());
      Assertions.assertEquals(ipv4.calculateChecksum(), ipv4.checksum());
      Assertions.assertEquals(newIpv4.calculateChecksum(), newIpv4.checksum());
      Assertions.assertEquals(newIpv4.ihl() * 4, newIpv4.size());

      Assertions.assertNotNull(ipv4.toString());
      Assertions.assertNotNull(newIpv4.toString());

      buffer.byteOrder(PacketBuffer.ByteOrder.LITTLE_ENDIAN);
      Assertions.assertNotEquals(91, ipv4.totalLength());
      // Assertions.assertNotEquals(0, ipv4.identification());
      Assertions.assertNotEquals(26284, ipv4.checksum());
      Assertions.assertEquals("109.0.168.192", ipv4.source().getHostAddress());
      Assertions.assertEquals("94.200.125.74", ipv4.destination().getHostAddress());
      Assertions.assertArrayEquals(new byte[0], ipv4.options());

      newBuffer.byteOrder(PacketBuffer.ByteOrder.LITTLE_ENDIAN);
      Assertions.assertNotEquals(91, newIpv4.totalLength());
      // Assertions.assertNotEquals(0, ipv4.identification());
      Assertions.assertNotEquals(26284, newIpv4.checksum());
      Assertions.assertEquals("109.0.168.192", newIpv4.source().getHostAddress());
      Assertions.assertEquals("94.200.125.74", newIpv4.destination().getHostAddress());
      Assertions.assertArrayEquals(new byte[] {127, 0, 0, 1}, newIpv4.options());

      newIpv4.options(new byte[] {0, 127});
      Assertions.assertArrayEquals(new byte[] {0, 127, 0, 1}, newIpv4.options());

      ipv4.checksum(1);
      Assertions.assertFalse(ipv4.isValidChecksum());

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              ipv4.ihl(7);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              ipv4.ihl(4);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              newIpv4.ihl(7);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              newIpv4.ihl(4);
            }
          });
      Assertions.assertThrows(
          IllegalStateException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              buffer.setIndex(0, 0).cast(Ip4.class);
            }
          });
      Assertions.assertThrows(
          IllegalStateException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              newBuffer.setIndex(0, 0).cast(Ip4.class);
            }
          });

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Ip4.newInstance(0, buffer);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Ip4.newInstance(61, buffer);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Ip4.newInstance(20, buffer.setIndex(0, 0));
            }
          });

      buffer.release();
      newBuffer.release();
    }
  }

  // see: https://github.com/ardikars/pcap/issues/149
  @Test
  void issue149()
      throws ErrorException, RadioFrequencyModeNotSupportedException, ActivatedException,
          InterfaceNotSupportTimestampTypeException, PromiscuousModePermissionDeniedException,
          InterfaceNotUpException, PermissionDeniedException, NoSuchDeviceException,
          TimestampPrecisionNotSupportedException {
    final byte[] bytes =
        Hexs.parseHex(
            "8a86831f94c4e86f38393dbf0800450000285ca440004006f3c9c0a832c43471c284cffe01bbea1008c16c50eee2501001f5a3be0000");
    Service service = Service.Creator.create("PcapService");
    try (final Pcap pcap = service.live(service.interfaces(), new DefaultLiveOptions())) {
      final PacketBuffer buffer =
          pcap.allocate(PacketBuffer.class)
              .capacity(bytes.length)
              .byteOrder(PacketBuffer.ByteOrder.BIG_ENDIAN);
      buffer.writeBytes(bytes);
      final Ethernet ethernet = buffer.cast(Ethernet.class);
      final Ip4 ip4 = buffer.readerIndex(ethernet.size()).cast(Ip4.class);
      final int checksum = ip4.checksum();
      final int calculatedChecksum = ip4.calculateChecksum();
      Assertions.assertEquals(checksum, calculatedChecksum);
      Assertions.assertTrue(ip4.isValidChecksum());
      Assertions.assertTrue(buffer.release());
    }
  }
}

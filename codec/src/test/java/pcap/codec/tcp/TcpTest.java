/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.tcp;

import java.net.Inet4Address;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.net.InetAddresses;
import pcap.common.util.Hexs;
import pcap.common.util.Strings;
import pcap.spi.PacketBuffer;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
public class TcpTest {

  private static final byte[] BYTES =
      Hexs.parseHex(
          "c82f01bbf3731826394d0f5b801808000f5900000101080a25cbc8a9d9dddf951703030022b15027736052b94d137aec334b9a023e897c9ffb0bfcaa30df75295c93cce2ba8ca0");

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

      final Tcp tcp = buffer.cast(Tcp.class);
      final Tcp comparison = Tcp.newInstance(tcp.size(), buffer);
      Assertions.assertEquals(tcp, comparison);

      Assertions.assertEquals(51247, tcp.sourcePort());
      Assertions.assertEquals(443, tcp.destinationPort());
      Assertions.assertEquals(4084406310L, tcp.sequenceNumber());
      Assertions.assertEquals(961351515, tcp.acknowledgmentNumber());
      Assertions.assertEquals(8, tcp.dataOffset());
      Assertions.assertFalse(tcp.ns());
      Assertions.assertFalse(tcp.cwr());
      Assertions.assertFalse(tcp.ece());
      Assertions.assertFalse(tcp.urg());
      Assertions.assertTrue(tcp.ack());
      Assertions.assertTrue(tcp.psh());
      Assertions.assertFalse(tcp.rst());
      Assertions.assertFalse(tcp.syn());
      Assertions.assertFalse(tcp.fin());
      Assertions.assertEquals(2048, tcp.windowSize());
      Assertions.assertEquals(3929, tcp.checksum());
      Assertions.assertEquals(0, tcp.urgentPointer());
      Assertions.assertEquals("0101080a25cbc8a9d9dddf95", Strings.hex(tcp.options()));
      Assertions.assertEquals(tcp.dataOffset() << 2, tcp.size());

      Inet4Address src =
          InetAddresses.fromBytesToInet4Address(new byte[] {(byte) 192, (byte) 168, 0, 109});
      Inet4Address dst =
          InetAddresses.fromBytesToInet4Address(new byte[] {74, 125, (byte) 200, 94});
      Assertions.assertTrue(tcp.isValidChecksum(src, dst, 39));
      Assertions.assertFalse(tcp.isValidChecksum(src, src, 39));

      Assertions.assertNotNull(tcp.toString());

      tcp.sourcePort(443);
      tcp.destinationPort(51247);
      tcp.sequenceNumber(1);
      tcp.acknowledgmentNumber(1);
      tcp.dataOffset(6);
      tcp.ns(true);
      tcp.cwr(true);
      tcp.ece(true);
      tcp.urg(true);
      tcp.ack(false);
      tcp.psh(false);
      tcp.rst(true);
      tcp.syn(true);
      tcp.fin(true);
      tcp.windowSize(4096);
      tcp.checksum(2);
      tcp.urgentPointer(0);
      tcp.options(new byte[] {127, 0, 0, 1});

      Assertions.assertEquals(443, tcp.sourcePort());
      Assertions.assertEquals(51247, tcp.destinationPort());
      Assertions.assertEquals(1, tcp.sequenceNumber());
      Assertions.assertEquals(1, tcp.acknowledgmentNumber());
      Assertions.assertEquals(6, tcp.dataOffset());
      Assertions.assertTrue(tcp.ns());
      Assertions.assertTrue(tcp.cwr());
      Assertions.assertTrue(tcp.ece());
      Assertions.assertTrue(tcp.urg());
      Assertions.assertFalse(tcp.ack());
      Assertions.assertFalse(tcp.psh());
      Assertions.assertTrue(tcp.rst());
      Assertions.assertTrue(tcp.syn());
      Assertions.assertTrue(tcp.fin());
      Assertions.assertEquals(4096, tcp.windowSize());
      Assertions.assertEquals(2, tcp.checksum());
      Assertions.assertEquals(0, tcp.urgentPointer());
      Assertions.assertArrayEquals(new byte[] {127, 0, 0, 1}, tcp.options());

      tcp.options(new byte[] {0, 127});
      Assertions.assertArrayEquals(new byte[] {0, 127, 0, 1}, tcp.options());

      Assertions.assertNotNull(tcp.toString());

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              tcp.dataOffset(4);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              tcp.dataOffset(16);
            }
          });
      Assertions.assertThrows(
          IllegalStateException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              buffer.setIndex(0, 0).cast(Tcp.class);
            }
          });

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Tcp.newInstance(0, buffer);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Tcp.newInstance(61, buffer);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Tcp.newInstance(20, buffer.setIndex(0, 0));
            }
          });

      buffer.release();
    }
  }

  @Test
  void flags()
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

      final Tcp tcp = buffer.cast(Tcp.class);

      tcp.ns(true);
      tcp.cwr(true);
      tcp.ece(true);
      tcp.urg(true);
      tcp.ack(true);
      tcp.psh(true);
      tcp.rst(true);
      tcp.syn(true);
      tcp.fin(true);

      Assertions.assertTrue(tcp.ns());
      Assertions.assertTrue(tcp.cwr());
      Assertions.assertTrue(tcp.ece());
      Assertions.assertTrue(tcp.urg());
      Assertions.assertTrue(tcp.ack());
      Assertions.assertTrue(tcp.psh());
      Assertions.assertTrue(tcp.rst());
      Assertions.assertTrue(tcp.syn());
      Assertions.assertTrue(tcp.fin());

      Assertions.assertNotNull(tcp.toString());

      tcp.ns(false);
      tcp.cwr(false);
      tcp.ece(false);
      tcp.urg(false);
      tcp.ack(false);
      tcp.psh(false);
      tcp.rst(false);
      tcp.syn(false);
      tcp.fin(false);

      Assertions.assertFalse(tcp.ns());
      Assertions.assertFalse(tcp.cwr());
      Assertions.assertFalse(tcp.ece());
      Assertions.assertFalse(tcp.urg());
      Assertions.assertFalse(tcp.ack());
      Assertions.assertFalse(tcp.psh());
      Assertions.assertFalse(tcp.rst());
      Assertions.assertFalse(tcp.syn());
      Assertions.assertFalse(tcp.fin());

      Assertions.assertNotNull(tcp.toString());

      tcp.ns(true);
      tcp.cwr(true);
      tcp.ece(true);
      tcp.urg(true);
      tcp.ack(true);
      tcp.psh(true);
      tcp.rst(true);
      tcp.syn(true);
      tcp.fin(true);

      Assertions.assertTrue(tcp.ns());
      Assertions.assertTrue(tcp.cwr());
      Assertions.assertTrue(tcp.ece());
      Assertions.assertTrue(tcp.urg());
      Assertions.assertTrue(tcp.ack());
      Assertions.assertTrue(tcp.psh());
      Assertions.assertTrue(tcp.rst());
      Assertions.assertTrue(tcp.syn());
      Assertions.assertTrue(tcp.fin());

      Assertions.assertNotNull(tcp.toString());

      tcp.ns(true);
      tcp.cwr(true);
      tcp.ece(true);
      tcp.urg(true);
      tcp.ack(true);
      tcp.psh(true);
      tcp.rst(true);
      tcp.syn(true);
      tcp.fin(true);

      Assertions.assertTrue(tcp.ns());
      Assertions.assertTrue(tcp.cwr());
      Assertions.assertTrue(tcp.ece());
      Assertions.assertTrue(tcp.urg());
      Assertions.assertTrue(tcp.ack());
      Assertions.assertTrue(tcp.psh());
      Assertions.assertTrue(tcp.rst());
      Assertions.assertTrue(tcp.syn());
      Assertions.assertTrue(tcp.fin());

      Assertions.assertNotNull(tcp.toString());

      tcp.ns(false);
      tcp.cwr(false);
      tcp.ece(false);
      tcp.urg(false);
      tcp.ack(false);
      tcp.psh(false);
      tcp.rst(false);
      tcp.syn(false);
      tcp.fin(false);

      Assertions.assertFalse(tcp.ns());
      Assertions.assertFalse(tcp.cwr());
      Assertions.assertFalse(tcp.ece());
      Assertions.assertFalse(tcp.urg());
      Assertions.assertFalse(tcp.ack());
      Assertions.assertFalse(tcp.psh());
      Assertions.assertFalse(tcp.rst());
      Assertions.assertFalse(tcp.syn());
      Assertions.assertFalse(tcp.fin());

      Assertions.assertNotNull(tcp.toString());

      tcp.ns(false);
      tcp.cwr(false);
      tcp.ece(false);
      tcp.urg(false);
      tcp.ack(false);
      tcp.psh(false);
      tcp.rst(false);
      tcp.syn(false);
      tcp.fin(false);

      Assertions.assertFalse(tcp.ns());
      Assertions.assertFalse(tcp.cwr());
      Assertions.assertFalse(tcp.ece());
      Assertions.assertFalse(tcp.urg());
      Assertions.assertFalse(tcp.ack());
      Assertions.assertFalse(tcp.psh());
      Assertions.assertFalse(tcp.rst());
      Assertions.assertFalse(tcp.syn());
      Assertions.assertFalse(tcp.fin());

      Assertions.assertNotNull(tcp.toString());

      buffer.release();
    }
  }
}

/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.sll;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import pcap.codec.ip.Ip4;
import pcap.codec.ip.Ip6;
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

class SllTest {

  private static final byte[] BYTES =
      Hexs.parseHex(
          "000003040006000000000000000008004500003ed4e54000401167c77f0000017f000001c23d0035002afe3d61ef01000001000000000000056461697379067562756e747503636f6d0000010001");

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
      final Sll sll = buffer.cast(Sll.class);
      final Sll comparison = Sll.newInstance(sll.size(), buffer);
      Assertions.assertEquals(sll, comparison);
      Assertions.assertEquals(sll.hashCode(), comparison.hashCode());

      Assertions.assertEquals(0, sll.packetType());
      Assertions.assertEquals(772, sll.addressType());
      Assertions.assertEquals(6, sll.addressLength());
      byte[] address = new byte[6];
      Assertions.assertArrayEquals(address, sll.address());
      Assertions.assertEquals(Ip4.TYPE, sll.protocol());

      sll.packetType(1);
      Assertions.assertEquals(1, sll.packetType());
      sll.addressType(1);
      Assertions.assertEquals(1, sll.addressType());
      sll.addressLength(8);
      Assertions.assertEquals(8, sll.addressLength());

      for (int i = 0; i < address.length; i++) {
        address[i] = (byte) i;
      }
      sll.addressLength(6);
      sll.address(address);
      Assertions.assertArrayEquals(address, sll.address());

      sll.addressLength(100); // max addr len is 8 bytes, will returns 8 bytes with zero values
      Assertions.assertArrayEquals(new byte[8], sll.address());
      sll.addressLength(0); // max addr len is 8 bytes, will returns 8 bytes with zero values
      Assertions.assertArrayEquals(new byte[8], sll.address());

      sll.addressLength(6);
      sll.address(null);

      sll.addressLength(0);
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              sll.address(new byte[] {9, 9, 9, 9, 9, 9, 9, 9, 9});
            }
          });
      sll.addressLength(100);
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              sll.address(new byte[] {});
            }
          });

      sll.protocol(Ip6.TYPE);
      Assertions.assertEquals(Ip6.TYPE, (sll.protocol() & 0xFFFF));

      Assertions.assertNotNull(sll.toString());

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Sll.newInstance(0, buffer);
            }
          });
      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              long oldWriter = buffer.writerIndex();
              long oldReader = buffer.readerIndex();
              buffer.setIndex(oldWriter, oldWriter);
              Sll.newInstance(16, buffer);
              buffer.setIndex(oldReader, oldWriter);
            }
          });
    }
  }
}

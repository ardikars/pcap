/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.loopback;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.util.Hexs;
import pcap.spi.PacketBuffer;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
public class LoopbackTest {

  private static final byte[] BYTES =
      Hexs.parseHex(
          "0200000045000034dab64000800600007f0000017f00000108177629b6f6447f000000008002fffffd3300000204ffd70103030801010402");

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

      final Loopback loopback = buffer.cast(Loopback.class);
      final Loopback comparison = Loopback.newInstance(loopback.size(), buffer);
      Assertions.assertEquals(loopback, comparison);

      Assertions.assertEquals(Integer.reverseBytes(2), loopback.family());

      loopback.family(Integer.reverseBytes(1));
      Assertions.assertEquals(Integer.reverseBytes(1), loopback.family());

      Assertions.assertTrue(loopback.toString() != null);

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Loopback.newInstance(1, buffer);
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
              Loopback.newInstance(4, buffer);
              buffer.setIndex(oldReader, oldWriter);
            }
          });
    }
  }
}

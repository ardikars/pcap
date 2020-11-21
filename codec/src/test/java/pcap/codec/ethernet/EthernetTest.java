/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ethernet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.net.MacAddress;
import pcap.common.util.Hexs;
import pcap.spi.PacketBuffer;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
public class EthernetTest {

  private static final byte[] BYTES = Hexs.parseHex("d80d17269cee8c8590c30b330800");

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

      final Ethernet ethernet = buffer.cast(Ethernet.class);
      final Ethernet comparison = Ethernet.newInstance(14, buffer);
      Assertions.assertEquals(ethernet, comparison);

      System.out.println(ethernet);

      Assertions.assertEquals(MacAddress.valueOf("d8:0d:17:26:9c:ee"), ethernet.destination());
      Assertions.assertEquals(MacAddress.valueOf("8c:85:90:c3:0b:33"), ethernet.source());
      Assertions.assertEquals(0x0800, ethernet.type());

      // write
      ethernet.destination(MacAddress.BROADCAST);
      ethernet.source(MacAddress.DUMMY);
      ethernet.type(0x0806);

      // read
      Assertions.assertEquals(MacAddress.BROADCAST, ethernet.destination());
      Assertions.assertEquals(MacAddress.DUMMY, ethernet.source());
      Assertions.assertEquals(0x0806, ethernet.type());

      // to string
      Assertions.assertNotNull(ethernet.toString());

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Ethernet.newInstance(0, buffer);
            }
          });

      Assertions.assertThrows(
          IllegalArgumentException.class,
          new Executable() {
            @Override
            public void execute() throws Throwable {
              Ethernet.newInstance(14, buffer.setIndex(0, 0));
            }
          });

      // release buffer
      buffer.release();
    }
  }
}

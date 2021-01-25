/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec;

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
import pcap.spi.exception.error.*;
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
    try (final Pcap pcap =
        service.live(service.interfaces(), new DefaultLiveOptions().immediate(false))) {
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

      Assertions.assertFalse(udp.equals(ethernet));
      Assertions.assertFalse(ethernet.equals(""));
      Assertions.assertFalse(ethernet.equals(ethernet2));
      Assertions.assertTrue(ethernet.equals(ethernet));
      Assertions.assertTrue(ethernet.hashCode() >= 0 || ethernet.hashCode() < 0);

      ethernetBuffer.release();
      ethernet2Buffer.release();
    }
  }
}

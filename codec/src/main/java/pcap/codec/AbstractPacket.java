/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import pcap.spi.PacketBuffer;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public abstract class AbstractPacket extends pcap.spi.Packet.Abstract {

  protected AbstractPacket(PacketBuffer buffer) {
    super(buffer);
  }

  protected static class Checksum {

    private Checksum() {
      //
    }

    public static int sum(final PacketBuffer buffer, final long offset, final int length) {
      int accumulation = 0;
      long size = offset + (length % 2 == 0 ? length : length - 1);
      for (long i = offset; i < size; i += 2) {
        accumulation += buffer.getShort(i) & 0xFFFF;
      }
      if (length % 2 > 0) {
        accumulation += ((buffer.getByte(offset + size)) & 0xFF) << 8;
      }
      return accumulation;
    }

    public static int calculate(
        PacketBuffer buffer,
        long offset,
        InetAddress srcAddr,
        InetAddress dstAddr,
        int protocol,
        int headerLength,
        int payloadLength) {
      boolean isIp = srcAddr instanceof Inet4Address && dstAddr instanceof Inet4Address;
      int accumulation = 0;
      ByteBuffer bb = ByteBuffer.allocate(isIp ? 12 : 40);
      bb.put(srcAddr.getAddress());
      bb.put(dstAddr.getAddress());
      bb.put((byte) 0);
      bb.put((byte) protocol);
      if (isIp) {
        bb.putShort((short) (headerLength + payloadLength));
      } else {
        bb.putInt(headerLength);
      }
      bb.rewind();

      for (int i = 0; i < bb.capacity() / 2; ++i) {
        accumulation += bb.getShort() & 0xFFFF;
      }

      accumulation += sum(buffer, offset, payloadLength + headerLength);

      accumulation = (accumulation >> 16 & 0xFFFF) + (accumulation & 0xFFFF);
      return (~accumulation & 0xFFFF);
    }
  }
}

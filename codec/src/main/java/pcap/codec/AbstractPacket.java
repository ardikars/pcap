/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Internal;

/**
 * Abstract packet
 *
 * @since 1.0.0
 */
public abstract class AbstractPacket extends pcap.spi.Packet.Abstract {

  protected AbstractPacket(PacketBuffer buffer) {
    super(buffer);
  }

  @Internal
  protected static final class Checksum {

    private Checksum() {
      //
    }

    @Internal
    public static int sum(final PacketBuffer buffer, final long offset, final int length) {
      int accumulation = 0;
      final boolean isEven = (length & 1) == 0;
      final long size = offset + (isEven ? length : length - 1);
      for (long i = offset; i < size; i += 2) {
        accumulation += buffer.getShort(i) & 0xFFFF;
      }
      if (!isEven) {
        accumulation += ((buffer.getByte(offset + size)) & 0xFF) << 8;
      }
      return accumulation;
    }

    @Internal
    public static int calculate(
        PacketBuffer buffer,
        long offset,
        InetAddress srcAddr,
        InetAddress dstAddr,
        int protocol,
        int headerLength,
        int payloadLength) {
      final boolean isIp = srcAddr instanceof Inet4Address && dstAddr instanceof Inet4Address;
      int accumulation = 0;
      final ByteBuffer bb = ByteBuffer.allocate(isIp ? 12 : 40);
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

      for (int i = 0; i < bb.capacity() >>> 1; ++i) {
        accumulation += bb.getShort() & 0xFFFF;
      }

      accumulation += sum(buffer, offset, payloadLength + headerLength);

      accumulation = (accumulation >> 16 & 0xFFFF) + (accumulation & 0xFFFF);
      return (~accumulation & 0xFFFF);
    }
  }
}

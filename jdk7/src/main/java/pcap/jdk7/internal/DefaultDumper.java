/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Pointer;
import java.util.Objects;
import pcap.spi.Dumper;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHeader;

class DefaultDumper implements Dumper {

  private final Pointer pointer;

  DefaultDumper(Pointer pointer) {
    this.pointer = pointer;
  }

  @Override
  public void dump(PacketHeader header, PacketBuffer buffer) {
    if (header == null) {
      throw new IllegalArgumentException("header: null (expected: header != null)");
    }
    if (buffer == null) {
      throw new IllegalArgumentException("buffer: null (expected: buffer != null)");
    }
    if (buffer.capacity() <= 0) {
      throw new IllegalArgumentException(
          String.format(
              "buffer.capacity: %d (expected: buffer.capacity(%d) > 0)",
              buffer.capacity(), buffer.capacity()));
    }
    if (buffer.readableBytes() < header.length()) {
      throw new IllegalArgumentException(
          String.format(
              "buffer.readableBytes(): %d (expected: buffer.readableBytes(%d) >= header.length(%d))",
              buffer.readableBytes(), buffer.readableBytes(), header.length()));
    }
    DefaultPacketHeader packetHeader = (DefaultPacketHeader) header;
    DefaultPacketBuffer packetBuffer = (DefaultPacketBuffer) buffer;
    Objects.requireNonNull(packetHeader.pointer);
    Objects.requireNonNull(packetBuffer.buffer);
    NativeMappings.pcap_dump(
        pointer, packetHeader.pointer, packetBuffer.buffer.share(packetBuffer.writerIndex()));
  }

  @Override
  public long position() {
    return NativeMappings.pcap_dump_ftell(pointer).longValue();
  }

  @Override
  public void flush() {
    NativeMappings.pcap_dump_flush(pointer);
  }

  @Override
  public void close() {
    NativeMappings.pcap_dump_close(pointer);
  }
}

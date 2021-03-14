/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import pcap.spi.Dumper;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHeader;

class DefaultDumper implements Dumper {

  static final Set<Reference<DefaultDumper>> REFS =
      Collections.synchronizedSet(new HashSet<Reference<DefaultDumper>>());
  static final ReferenceQueue<DefaultDumper> RQ = new ReferenceQueue<DefaultDumper>();

  private final Pointer pointer;
  private final Pointer hdrPtr; // for copying header
  private final DumperReference reference;

  DefaultDumper(Pointer pointer) {
    this.pointer = pointer;
    long address = Native.malloc(DefaultPacketHeader.SIZEOF);
    this.hdrPtr = new Pointer(address);
    this.reference = new DumperReference(address, this, RQ);
    REFS.add(reference);
    DumperReference ref;
    while ((ref = (DumperReference) RQ.poll()) != null) {
      if (ref.address > 0L) {
        Native.free(ref.address);
        ref.address = 0L;
        REFS.remove(ref);
      }
    }
  }

  static void setNativeLong(Pointer ptr, long offset, long value, int longSize) {
    if (longSize == 8) {
      ptr.setLong(offset, value);
    } else {
      ptr.setInt(offset, (int) value);
    }
  }

  @Override
  public void dump(PacketHeader header, PacketBuffer buffer) {
    Utils.requireNonNull(header, "header: null (expected: header != null).");
    Utils.requireNonNull(buffer, "buffer: null (expected: buffer != null).");
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
    DefaultPacketBuffer packetBuffer = (DefaultPacketBuffer) buffer;
    setNativeLong(
        hdrPtr, DefaultTimestamp.TV_SEC_OFFSET, header.timestamp().second(), Native.LONG_SIZE);
    setNativeLong(
        hdrPtr,
        DefaultTimestamp.TV_USEC_OFFSET,
        header.timestamp().microSecond(),
        Native.LONG_SIZE);
    hdrPtr.setInt(DefaultPacketHeader.CAPLEN_OFFSET, header.captureLength());
    hdrPtr.setInt(DefaultPacketHeader.LEN_OFFSET, header.length());
    NativeMappings.pcap_dump(
        pointer, hdrPtr, packetBuffer.buffer.share(packetBuffer.readerIndex()));
  }

  @Override
  public long position() {
    return NativeMappings.PLATFORM_DEPENDENT.pcap_dump_ftell(pointer).longValue();
  }

  @Override
  public void flush() {
    NativeMappings.pcap_dump_flush(pointer);
  }

  @Override
  public void close() {
    NativeMappings.pcap_dump_close(pointer);
  }

  static final class DumperReference extends PhantomReference<DefaultDumper> {

    long address;

    DumperReference(long address, DefaultDumper referent, ReferenceQueue<? super DefaultDumper> q) {
      super(referent, q);
      this.address = address;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      DumperReference that = (DumperReference) o;
      return hashCode() == that.hashCode();
    }

    @Override
    public int hashCode() {
      return Objects.hash(address);
    }
  }
}

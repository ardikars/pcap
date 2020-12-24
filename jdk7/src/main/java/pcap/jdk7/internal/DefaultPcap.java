/*
 * Copyright (c) 2020 Pcap Project
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
import java.util.Set;
import pcap.spi.*;
import pcap.spi.annotation.Version;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.exception.error.NotActivatedException;

class DefaultPcap implements Pcap {

  static final Set<Reference<DefaultPcap>> REFS =
      Collections.synchronizedSet(new HashSet<Reference<DefaultPcap>>());

  static final ReferenceQueue<DefaultPcap> RQ = new ReferenceQueue<DefaultPcap>();

  private static final Object LOCK = new Object();

  final Pointer pointer;
  final int netmask;
  final DefaultStatistics statistics;
  final PcapReference reference;

  DefaultPcap(Pointer pointer, int netmask) {
    this.pointer = pointer;
    this.netmask = netmask;
    this.statistics = new DefaultStatistics();
    this.reference =
        new PcapReference(
            com.sun.jna.Pointer.nativeValue(pointer),
            com.sun.jna.Pointer.nativeValue(statistics.pointer),
            this,
            RQ);
    REFS.add(reference);
    PcapReference ref;
    while ((ref = (PcapReference) RQ.poll()) != null) {
      if (ref.pcap > 0 && ref.stats > 0) {
        NativeMappings.pcap_close(new com.sun.jna.Pointer(ref.pcap));
        Native.free(ref.stats);
      }
    }
  }

  static Timestamp.Precision timestampPrecision(int rc) {
    if (Timestamp.Precision.NANO.value() == rc) {
      return Timestamp.Precision.NANO;
    } else {
      return Timestamp.Precision.MICRO;
    }
  }

  @Override
  public DefaultDumper dumpOpen(String file) throws ErrorException {
    if (Utils.blank(file)) {
      throw new IllegalArgumentException("file: null (expected: file != null && notBlank(file))");
    }
    Pointer dumper = NativeMappings.pcap_dump_open(pointer, file);
    nullCheck(dumper);
    return new DefaultDumper(dumper);
  }

  @Override
  @Version(major = 1, minor = 7, patch = 2)
  public DefaultDumper dumpOpenAppend(String file) throws ErrorException {
    if (Utils.blank(file)) {
      throw new IllegalArgumentException("file: null (expected: file != null && notBlank(file))");
    }
    Version version = Utils.getVersion(DefaultPcap.class, "dumpOpenAppend", String.class);
    Utils.validateVersion(version);
    Pointer dumper = NativeMappings.PLATFORM_DEPENDENT.pcap_dump_open_append(pointer, file);
    nullCheck(dumper);
    return new DefaultDumper(dumper);
  }

  @Override
  public void setFilter(String filter, boolean optimize) throws ErrorException {
    if (Utils.blank(filter)) {
      throw new IllegalArgumentException(
          "filter: null (expected: filter != null && notBlank(filter))");
    }
    int rc;
    NativeMappings.bpf_program fp = new NativeMappings.bpf_program();

    if (Utils.MAJOR > 1 || (Utils.MAJOR == 1 && Utils.MINOR >= 8)) {
      // in libpcap 1.8.0 and later is newly thread-safe.
      rc = NativeMappings.pcap_compile(pointer, fp, filter, optimize ? 1 : 0, netmask);
    } else {
      synchronized (LOCK) {
        rc = NativeMappings.pcap_compile(pointer, fp, filter, optimize ? 1 : 0, netmask);
      }
    }

    compileCheck(rc, fp);

    rc = NativeMappings.pcap_setfilter(pointer, fp);
    filterCheck(rc, fp);
    NativeMappings.pcap_freecode(fp);
  }

  @Override
  public <T> void loop(int count, final PacketHandler<T> handler, final T args)
      throws BreakException, ErrorException {
    if (handler == null) {
      throw new IllegalArgumentException("handler: null (expected: handler != null)");
    }
    int rc =
        NativeMappings.pcap_loop(
            pointer,
            count,
            new NativeMappings.pcap_handler() {
              @Override
              public void got_packet(Pointer user, Pointer header, Pointer packet) {
                DefaultPacketHeader packetHeader = new DefaultPacketHeader(header);
                DefaultPacketBuffer packetBuffer =
                    new DefaultPacketBuffer(
                        packet,
                        PacketBuffer.ByteOrder.BIG_ENDIAN,
                        packetHeader.captureLength(),
                        0,
                        packetHeader.captureLength());
                handler.gotPacket(args, packetHeader, packetBuffer);
              }
            },
            Pointer.NULL);
    loopCheck(rc);
  }

  @Override
  public PacketBuffer next(PacketHeader header) {
    if (header == null) {
      throw new IllegalArgumentException("header: null (expected: header != null)");
    }
    PacketBuffer buffer;
    final DefaultPacketHeader[] packetHeader = new DefaultPacketHeader[1];
    packetHeader[0] = (DefaultPacketHeader) header;
    final DefaultPacketBuffer[] packetBuffer = new DefaultPacketBuffer[1];
    int rc =
        NativeMappings.pcap_dispatch(
            pointer,
            1,
            new NativeMappings.pcap_handler() {
              @Override
              public void got_packet(Pointer user, Pointer header, Pointer packet) {
                packetHeader[0].setPointer(header);
                packetBuffer[0] =
                    new DefaultPacketBuffer(
                        packet,
                        PacketBuffer.ByteOrder.BIG_ENDIAN,
                        packetHeader[0].captureLength(),
                        0,
                        packetHeader[0].captureLength());
              }
            },
            Pointer.NULL);
    if (rc > 0) {
      buffer = packetBuffer[0];
    } else {
      buffer = null;
    }

    return buffer;
  }

  @Override
  public void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
      throws BreakException, ErrorException, TimeoutException {
    if (packetHeader == null) {
      throw new IllegalArgumentException("header: null (expected: header != null)");
    }
    if (packetBuffer == null) {
      throw new IllegalArgumentException("buffer: null (expected: buffer != null)");
    }
    DefaultPacketHeader header = (DefaultPacketHeader) packetHeader;
    DefaultPacketBuffer buffer = (DefaultPacketBuffer) packetBuffer;
    int rc = NativeMappings.pcap_next_ex(pointer, header.reference, buffer.reference);
    nextExCheck(rc, header, buffer);
  }

  @Override
  public <T> void dispatch(int count, final PacketHandler<T> handler, final T args)
      throws BreakException, ErrorException, TimeoutException {
    if (handler == null) {
      throw new IllegalArgumentException("handler: null (expected: handler != null)");
    }
    int rc =
        NativeMappings.pcap_dispatch(
            pointer,
            count,
            new NativeMappings.pcap_handler() {
              @Override
              public void got_packet(Pointer user, Pointer header, Pointer packet) {
                DefaultPacketHeader packetHeader = new DefaultPacketHeader(header);
                DefaultPacketBuffer packetBuffer =
                    new DefaultPacketBuffer(
                        packet,
                        PacketBuffer.ByteOrder.BIG_ENDIAN,
                        packetHeader.captureLength(),
                        0,
                        packetHeader.captureLength());
                handler.gotPacket(args, packetHeader, packetBuffer);
              }
            },
            Pointer.NULL);
    dispatchCheck(rc);
  }

  @Override
  public Statistics stats() throws ErrorException {
    int rc = NativeMappings.pcap_stats(pointer, statistics.pointer);
    statsCheck(rc);
    return statistics;
  }

  @Override
  public void breakLoop() {
    NativeMappings.pcap_breakloop(pointer);
  }

  @Override
  public void sendPacket(PacketBuffer directBuffer) throws ErrorException {
    checkBuffer(directBuffer);
    DefaultPacketBuffer buffer = (DefaultPacketBuffer) directBuffer;
    int rc =
        NativeMappings.pcap_sendpacket(
            pointer, buffer.buffer.share(buffer.readerIndex()), (int) directBuffer.readableBytes());
    injectCheck(rc);
  }

  @Override
  public int inject(PacketBuffer directBuffer) throws ErrorException {
    checkBuffer(directBuffer);
    DefaultPacketBuffer buffer = (DefaultPacketBuffer) directBuffer;
    int rc =
        NativeMappings.pcap_inject(
            pointer, buffer.buffer.share(buffer.readerIndex()), (int) directBuffer.readableBytes());
    injectCheck(rc);
    return rc;
  }

  @Override
  public void setDirection(Direction direction) throws ErrorException {
    if (direction == null) {
      throw new IllegalArgumentException("direction: null (expected: direction != null)");
    }
    int result;
    if (Direction.PCAP_D_IN == direction) {
      result = NativeMappings.pcap_setdirection(pointer, 1);
    } else if (Direction.PCAP_D_OUT == direction) {
      result = NativeMappings.pcap_setdirection(pointer, 2);
    } else {
      result = NativeMappings.pcap_setdirection(pointer, 0);
    }
    directionCheck(result);
  }

  @Override
  public boolean isSwapped() throws NotActivatedException {
    return swappedCheck(NativeMappings.pcap_is_swapped(pointer));
  }

  @Override
  public Timestamp.Precision getTimestampPrecision() {
    return timestampPrecision(NativeMappings.PLATFORM_DEPENDENT.pcap_get_tstamp_precision(pointer));
  }

  @Override
  public int majorVersion() {
    return NativeMappings.pcap_major_version(pointer);
  }

  @Override
  public int minorVersion() {
    return NativeMappings.pcap_minor_version(pointer);
  }

  @Override
  public int snapshot() {
    return NativeMappings.pcap_snapshot(pointer);
  }

  @Override
  public boolean getNonBlock() throws ErrorException {
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    int rc = NativeMappings.pcap_getnonblock(pointer, errbuf);
    getNonBlockCheck(rc);
    return rc == NativeMappings.TRUE;
  }

  @Override
  public void setNonBlock(boolean blocking) throws ErrorException {
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    int rc = NativeMappings.pcap_setnonblock(pointer, blocking ? 1 : 0, errbuf);
    setNonBlockCheck(rc);
  }

  @Override
  public int datalink() {
    return NativeMappings.pcap_datalink(pointer);
  }

  @Override
  public void close() {
    NativeMappings.pcap_close(pointer);
    com.sun.jna.Native.free(com.sun.jna.Pointer.nativeValue(statistics.pointer));
    reference.pcap = 0L;
    reference.stats = 0L;
  }

  @Override
  public <T> T allocate(Class<T> cls) throws IllegalArgumentException {
    if (cls == null) {
      throw new IllegalArgumentException(
          "type: null (expected: type is PacketHeader.class or PacketBuffer.class)");
    }

    if (cls.isAssignableFrom(PacketHeader.class)) {
      return (T) new DefaultPacketHeader();
    } else if (cls.isAssignableFrom(PacketBuffer.class)) {
      DefaultPacketBuffer buffer = new DefaultPacketBuffer();
      return (T) buffer;
    }

    throw new IllegalArgumentException("Class: " + cls + " is unsupported.");
  }

  void nullCheck(Pointer newPointer) throws ErrorException {
    if (newPointer == null) {
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  void compileCheck(int rc, NativeMappings.bpf_program fp) throws ErrorException {
    if (rc != NativeMappings.OK) {
      NativeMappings.pcap_freecode(fp);
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  void filterCheck(int rc, NativeMappings.bpf_program fp) throws ErrorException {
    if (rc != NativeMappings.OK) {
      NativeMappings.pcap_freecode(fp);
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  void loopCheck(int rc) throws BreakException, ErrorException {
    if (rc == 0) {
      return;
    } else if (rc == -2) {
      throw new BreakException("Break loop.");
    } else {
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  void dispatchCheck(int rc) throws ErrorException, BreakException {
    if (rc < 0) {
      if (rc == -1) {
        throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
      } else if (rc == -2) {
        throw new BreakException("Break loop.");
      } else {
        throw new ErrorException("Generic error");
      }
    }
  }

  void nextExCheck(int rc, DefaultPacketHeader header, DefaultPacketBuffer buffer)
      throws BreakException, ErrorException, TimeoutException {
    if (rc == 0) {
      throw new TimeoutException("Read packet timeout.");
    } else if (rc == 1) {
      header.useReference();
      buffer.useReference(header);
    } else {
      if (rc == -2) {
        throw new BreakException("Break loop.");
      } else {
        throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
      }
    }
  }

  void statsCheck(int rc) throws ErrorException {
    if (rc < 0) {
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  void injectCheck(int rc) throws ErrorException {
    if (rc < 0) {
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  void directionCheck(int result) throws ErrorException {
    if (result < 0) {
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  void getNonBlockCheck(int rc) throws ErrorException {
    if (rc < 0) {
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  void setNonBlockCheck(int rc) throws ErrorException {
    if (rc < 0) {
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  boolean swappedCheck(int swapped) throws NotActivatedException {
    if (swapped == NativeMappings.TRUE) {
      return true;
    } else if (swapped == NativeMappings.FALSE) {
      return false;
    } else {
      if (swapped == -3) {
        throw new NotActivatedException("Not activated.");
      } else {
        return false;
      }
    }
  }

  void checkBuffer(PacketBuffer directBuffer) {
    if (directBuffer == null) {
      throw new IllegalArgumentException("buffer: null (expected: buffer != null)");
    }
    if (directBuffer.readableBytes() <= 0) {
      throw new IllegalArgumentException(
          "cannot send empty buffer (buffer is not readable/readable bytes is 0)");
    }
    if (directBuffer.capacity() <= 0) {
      throw new IllegalArgumentException(
          String.format(
              "buffer.capacity: %d (expected: buffer.capacity(%d) > 0)",
              directBuffer.capacity(), directBuffer.capacity()));
    }
  }

  static final class PcapReference extends PhantomReference<DefaultPcap> {

    long pcap;
    long stats;

    PcapReference(
        long pcapRef, long statsRef, DefaultPcap referent, ReferenceQueue<? super DefaultPcap> q) {
      super(referent, q);
      this.pcap = pcapRef;
      this.stats = statsRef;
    }
  }
}

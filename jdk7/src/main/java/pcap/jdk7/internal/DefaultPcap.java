/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketFilter;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;
import pcap.spi.Pcap;
import pcap.spi.Selection;
import pcap.spi.Selector;
import pcap.spi.Statistics;
import pcap.spi.Timestamp;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.exception.error.NotActivatedException;

class DefaultPcap implements Pcap {

  static final Set<Reference<DefaultPcap>> REFS =
      Collections.synchronizedSet(new HashSet<Reference<DefaultPcap>>());
  static final ReferenceQueue<DefaultPcap> RQ = new ReferenceQueue<DefaultPcap>();
  private static final Logger LOG = LoggerFactory.getLogger(DefaultPcap.class);
  final Pointer pointer;
  final int netmask;
  final int datalink;
  final DefaultStatistics statistics;
  final PcapReference reference;

  AbstractSelector<?> selector;

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
        REFS.remove(ref);
      }
    }
    this.datalink = NativeMappings.pcap_datalink(pointer);
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
    checkOpenState();
    Utils.requireNonBlank(file, "file: null (expected: file != null && notBlank(file))");
    Pointer dumper = NativeMappings.pcap_dump_open(pointer, file);
    nullCheck(dumper);
    return new DefaultDumper(dumper);
  }

  @Override
  public DefaultDumper dumpOpenAppend(String file) throws ErrorException {
    checkOpenState();
    Utils.validateVersion(1, 7, 0);
    Utils.requireNonBlank(file, "file: null (expected: file != null && notBlank(file))");
    Pointer dumper = NativeMappings.PLATFORM_DEPENDENT.pcap_dump_open_append(pointer, file);
    nullCheck(dumper);
    return new DefaultDumper(dumper);
  }

  @Override
  public PacketFilter compile(String filter, boolean optimize) throws ErrorException {
    checkOpenState();
    Utils.requireNonBlank(filter, "filter: null (expected: filter != null && notBlank(filter))");
    return new BerkeleyPacketFilter(pointer, filter, optimize, netmask);
  }

  @Override
  public void setFilter(PacketFilter filter) throws ErrorException {
    checkOpenState();
    Utils.requireNonNull(filter, "filter: null (expected: filter != null)");
    BerkeleyPacketFilter packetFilter = (BerkeleyPacketFilter) filter;
    int rc = NativeMappings.pcap_setfilter(pointer, packetFilter.fp);
    filterCheck(rc, packetFilter.fp);
  }

  @Override
  public void setFilter(String filter, boolean optimize) throws ErrorException {
    try (PacketFilter compiled = compile(filter, optimize)) {
      setFilter(compiled);
    } catch (IllegalStateException | IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      throw new ErrorException(e.getMessage());
    }
  }

  @Override
  public <T> void loop(int count, final PacketHandler<T> handler, final T args)
      throws BreakException, ErrorException {
    checkOpenState();
    Utils.requireNonNull(handler, "handler: null (expected: handler != null)");
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
                        packetHeader.length(),
                        0,
                        packetHeader.captureLength());
                handler.gotPacket(args, packetHeader, packetBuffer);
              }
            },
            Pointer.NULL);
    loopCheck(rc);
  }

  @Override
  public PacketBuffer next(final PacketHeader header) {
    checkOpenState();
    Utils.requireNonNull(header, "header: null (expected: header != null)");
    final DefaultPacketHeader packetHeader = (DefaultPacketHeader) header;
    final AtomicReference<DefaultPacketBuffer> packetBuffer =
        new AtomicReference<DefaultPacketBuffer>(null);
    int rc =
        NativeMappings.pcap_dispatch(
            pointer,
            1,
            new NativeMappings.pcap_handler() {
              @Override
              public void got_packet(Pointer user, Pointer header, Pointer packet) {
                packetHeader.setPointer(header);
                packetBuffer.set(
                    new DefaultPacketBuffer(
                        packet,
                        PacketBuffer.ByteOrder.BIG_ENDIAN,
                        packetHeader.length(),
                        0,
                        packetHeader.captureLength()));
              }
            },
            Pointer.NULL);
    if (rc > 0) {
      return packetBuffer.get();
    } else {
      return null;
    }
  }

  @Override
  public void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
      throws BreakException, ErrorException, TimeoutException {
    checkOpenState();
    Utils.requireNonNull(packetHeader, "header: null (expected: header != null)");
    Utils.requireNonNull(packetBuffer, "buffer: null (expected: buffer != null)");
    DefaultPacketHeader header = (DefaultPacketHeader) packetHeader;
    DefaultPacketBuffer buffer = (DefaultPacketBuffer) packetBuffer;
    int rc = NativeMappings.pcap_next_ex(pointer, header.reference, buffer.reference);
    nextExCheck(rc, header, buffer);
  }

  @Override
  public <T> void dispatch(int count, final PacketHandler<T> handler, final T args)
      throws BreakException, ErrorException, TimeoutException {
    checkOpenState();
    Utils.requireNonNull(handler, "handler: null (expected: handler != null)");
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
                        packetHeader.length(),
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
    checkOpenState();
    int rc = NativeMappings.pcap_stats(pointer, statistics.pointer);
    statsCheck(rc);
    return statistics;
  }

  @Override
  public void breakLoop() {
    checkOpenState();
    NativeMappings.pcap_breakloop(pointer);
  }

  @Override
  public void sendPacket(PacketBuffer directBuffer) throws ErrorException {
    checkOpenState();
    checkBuffer(directBuffer);
    DefaultPacketBuffer buffer = (DefaultPacketBuffer) directBuffer;
    int rc =
        NativeMappings.pcap_sendpacket(
            pointer, buffer.buffer.share(buffer.readerIndex()), (int) directBuffer.readableBytes());
    injectCheck(rc);
  }

  @Override
  public int inject(PacketBuffer directBuffer) throws ErrorException {
    checkOpenState();
    checkBuffer(directBuffer);
    DefaultPacketBuffer buffer = (DefaultPacketBuffer) directBuffer;
    final int readableBytes = (int) directBuffer.readableBytes();
    int rc =
        NativeMappings.PLATFORM_DEPENDENT.pcap_inject(
            pointer, buffer.buffer.share(buffer.readerIndex()), readableBytes);
    injectCheck(rc);
    return rc;
  }

  @Override
  public void setDirection(Direction direction) throws ErrorException {
    checkOpenState();
    Utils.requireNonNull(direction, "direction: null (expected: direction != null)");
    int result;
    if (Direction.PCAP_D_IN == direction) {
      result = NativeMappings.PLATFORM_DEPENDENT.pcap_setdirection(pointer, 1);
    } else if (Direction.PCAP_D_OUT == direction) {
      result = NativeMappings.PLATFORM_DEPENDENT.pcap_setdirection(pointer, 2);
    } else {
      result = NativeMappings.PLATFORM_DEPENDENT.pcap_setdirection(pointer, 0);
    }
    directionCheck(result);
  }

  @Override
  public boolean isSwapped() throws NotActivatedException {
    checkOpenState();
    return swappedCheck(NativeMappings.pcap_is_swapped(pointer));
  }

  @Override
  public Timestamp.Precision getTimestampPrecision() {
    checkOpenState();
    return timestampPrecision(NativeMappings.PLATFORM_DEPENDENT.pcap_get_tstamp_precision(pointer));
  }

  @Override
  public int majorVersion() {
    checkOpenState();
    return NativeMappings.pcap_major_version(pointer);
  }

  @Override
  public int minorVersion() {
    checkOpenState();
    return NativeMappings.pcap_minor_version(pointer);
  }

  @Override
  public int snapshot() {
    checkOpenState();
    return NativeMappings.pcap_snapshot(pointer);
  }

  @Override
  public boolean getNonBlock() throws ErrorException {
    checkOpenState();
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    int rc = NativeMappings.pcap_getnonblock(pointer, errbuf);
    getNonBlockCheck(rc);
    return rc == NativeMappings.TRUE;
  }

  @Override
  public void setNonBlock(boolean blocking) throws ErrorException {
    checkOpenState();
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    int rc = NativeMappings.pcap_setnonblock(pointer, blocking ? 1 : 0, errbuf);
    setNonBlockCheck(rc);
  }

  @Override
  public int datalink() {
    checkOpenState();
    return datalink;
  }

  @Override
  public Object id() throws IllegalAccessException {
    checkOpenState();
    return getId(NativeMappings.RESTRICTED_LEVEL);
  }

  Object getId(int restrictedLevel) throws IllegalAccessException {
    if (restrictedLevel > 0) {
      if (restrictedLevel > 1) {
        LOG.warn("Calling restricted method Pcap#id().");
      }
      try {
        if (Platform.isWindows() || Platform.isWindowsCE()) {
          final NativeMappings.HANDLE handle =
              NativeMappings.PLATFORM_DEPENDENT.pcap_getevent(pointer);
          return Pointer.nativeValue(handle.getPointer());
        } else {
          return NativeMappings.PLATFORM_DEPENDENT.pcap_get_selectable_fd(pointer);
        }
      } catch (UnsatisfiedLinkError | NullPointerException e) {
        return null;
      }
    } else {
      LOG.warn(NativeMappings.RESTRICTED_MESSAGE);
      LOG.warn(NativeMappings.RESTRICTED_PROPERTY_VALUE);
      throw new IllegalAccessException(NativeMappings.RESTRICTED_MESSAGE);
    }
  }

  @Override
  public void close() {
    checkOpenState();
    if (selector != null && !selector.isClosed) {
      selector.cancel(this);
    }
    NativeMappings.pcap_close(pointer);
    com.sun.jna.Native.free(com.sun.jna.Pointer.nativeValue(statistics.pointer));
    reference.pcap = 0L;
    reference.stats = 0L;
  }

  @Override
  public Selection register(Selector selector, int interestOperations, Object attachment)
      throws IllegalArgumentException, IllegalStateException {
    checkOpenState();
    if (selector instanceof AbstractSelector<?>) {
      AbstractSelector<?> s = (AbstractSelector) selector;
      return s.register(this, interestOperations, attachment);
    }
    throw new IllegalArgumentException("Invalid selector type.");
  }

  @Override
  public <T> T allocate(Class<T> cls) throws IllegalArgumentException {
    checkOpenState();
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

    throw new IllegalArgumentException(String.format("Class: %s is unsupported.", cls));
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DefaultPcap that = (DefaultPcap) o;
    return pointer.equals(that.pointer);
  }

  @Override
  public int hashCode() {
    return Objects.hash(Pointer.nativeValue(pointer));
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
    Utils.requireNonNull(directBuffer, "buffer: null (expected: buffer != null)");
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

  void checkOpenState() {
    if (!(reference.pcap != 0L && reference.stats != 0L)) {
      throw new IllegalStateException("Pcap handle is closed.");
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

    @Override
    public boolean equals(Object o) {
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      PcapReference reference = (PcapReference) o;
      return hashCode() == reference.hashCode();
    }

    @Override
    public int hashCode() {
      return Objects.hash(pcap, stats);
    }
  }
}

package pcap.api.jdk7;

import com.sun.jna.Pointer;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.exception.error.NotActivatedException;

public class DefaultPcap implements Pcap {

  final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
  final ReentrantReadWriteLock.ReadLock readLock = lock.readLock();
  final ReentrantReadWriteLock.WriteLock writeLock = lock.writeLock();

  final Pointer pointer;
  final int netmask;

  final DefaultStatistics statistics = new DefaultStatistics();

  DefaultPcap(Pointer pointer, int netmask) {
    this.pointer = pointer;
    this.netmask = netmask;
  }

  @Override
  public DefaultDumper dumpOpen(String file) throws ErrorException {
    Pointer dumper;
    readLock.lock();
    try {
      dumper = NativeMappings.pcap_dump_open(pointer, file);
      nullCheck(dumper);
    } finally {
      readLock.unlock();
    }
    return new DefaultDumper(dumper);
  }

  @Override
  public DefaultDumper dumpOpenAppend(String file) throws ErrorException {
    Pointer dumper;
    readLock.lock();
    try {
      dumper = NativeMappings.pcap_dump_open_append(pointer, file);
      nullCheck(dumper);
    } finally {
      readLock.unlock();
    }
    return new DefaultDumper(dumper);
  }

  @Override
  public void setFilter(String filter, boolean optimize) throws ErrorException {
    int rc;
    NativeMappings.bpf_program fp = new NativeMappings.bpf_program();
    writeLock.lock();
    try {
      rc = NativeMappings.pcap_compile(pointer, fp, filter, optimize ? 1 : 0, netmask);
      compileCheck(rc, fp);
    } finally {
      writeLock.unlock();
    }
    readLock.lock();
    try {
      rc = NativeMappings.pcap_setfilter(pointer, fp);
      filterCheck(rc, fp);
      NativeMappings.pcap_freecode(fp);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public <T> void loop(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    readLock.lock();
    try {
      int rc =
          NativeMappings.pcap_loop(
              pointer,
              count,
              new NativeMappings.pcap_handler() {
                @Override
                public void got_packet(
                    Pointer user, DefaultPacketHeader header, DefaultPacketBuffer packet) {
                  packet.setBuffer(header.captureLength());
                  handler.gotPacket(args, header, packet);
                }
              },
              Pointer.NULL);
      loopCheck(rc);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public void nextEx(PacketBuffer packetBuffer, PacketHeader packetHeader)
      throws BreakException, TimeoutException, ErrorException {
    nextEx(packetHeader, packetBuffer);
  }

  @Override
  public void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
      throws BreakException, TimeoutException, ErrorException {
    DefaultPacketHeader header = (DefaultPacketHeader) packetHeader;
    DefaultPacketBuffer buffer = (DefaultPacketBuffer) packetBuffer;
    readLock.lock();
    try {
      int rc = NativeMappings.pcap_next_ex(pointer, header.reference, buffer.reference);
      nextExCheck(rc, header, buffer);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public <T> void dispatch(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    int rc;
    readLock.lock();
    try {
      rc =
          NativeMappings.pcap_dispatch(
              pointer,
              count,
              new NativeMappings.pcap_handler() {
                @Override
                public void got_packet(
                    Pointer user, DefaultPacketHeader header, DefaultPacketBuffer packet) {
                  packet.setBuffer(header.captureLength());
                  handler.gotPacket(args, header, packet);
                }
              },
              Pointer.NULL);
      dispatchCheck(rc);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public Statistics stats() throws ErrorException {
    int rc;
    readLock.lock();
    try {
      rc = NativeMappings.pcap_stats(pointer, statistics);
      statsCheck(rc);
    } finally {
      readLock.unlock();
    }
    return statistics;
  }

  @Override
  public Status status() throws ErrorException {
    return stats();
  }

  @Override
  public void breakLoop() {
    readLock.lock();
    try {
      NativeMappings.pcap_breakloop(pointer);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public void sendPacket(PacketBuffer directBuffer, int size) throws ErrorException {
    directBuffer.writerIndex(size);
    sendPacket(directBuffer);
  }

  @Override
  public void send(PacketBuffer directBuffer, int size) throws ErrorException {
    sendPacket(directBuffer, size);
  }

  @Override
  public void send(PacketBuffer directBuffer) throws ErrorException {
    sendPacket(directBuffer);
  }

  @Override
  public void sendPacket(PacketBuffer directBuffer) throws ErrorException {
    DefaultPacketBuffer buffer = (DefaultPacketBuffer) directBuffer;
    readLock.lock();
    try {
      int rc =
          NativeMappings.pcap_sendpacket(pointer, buffer.buffer, (int) directBuffer.writerIndex());
      sendCheck(rc);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public void setDirection(Direction direction) throws ErrorException {
    int result = 0;
    readLock.lock();
    try {
      if (Direction.PCAP_D_IN == direction) {
        result = NativeMappings.pcap_setdirection(pointer, 1);
      } else if (Direction.PCAP_D_OUT == direction) {
        result = NativeMappings.pcap_setdirection(pointer, 2);
      } else {
        result = NativeMappings.pcap_setdirection(pointer, 0);
      }
      directionCheck(result);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public boolean isSwapped() throws NotActivatedException {
    int rc;
    readLock.lock();
    try {
      rc = NativeMappings.pcap_is_swapped(pointer);
    } finally {
      readLock.unlock();
    }
    return swappedCheck(rc);
  }

  @Override
  public int majorVersion() {
    int rc;
    readLock.lock();
    try {
      rc = NativeMappings.pcap_major_version(pointer);
    } finally {
      readLock.unlock();
    }
    return rc;
  }

  @Override
  public int minorVersion() {
    int rc;
    readLock.lock();
    try {
      rc = NativeMappings.pcap_minor_version(pointer);
    } finally {
      readLock.unlock();
    }
    return rc;
  }

  @Override
  public int snapshot() {
    int rc;
    readLock.lock();
    try {
      rc = NativeMappings.pcap_snapshot(pointer);
    } finally {
      readLock.unlock();
    }
    return rc;
  }

  @Override
  public boolean getNonBlock() throws ErrorException {
    int rc;
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    readLock.lock();
    try {
      rc = NativeMappings.pcap_getnonblock(pointer, errbuf);
      getNonBlockCheck(rc);
    } finally {
      readLock.unlock();
    }
    return rc == NativeMappings.TRUE;
  }

  @Override
  public void setNonBlock(boolean blocking) throws ErrorException {
    int rc;
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    readLock.lock();
    try {
      rc = NativeMappings.pcap_setnonblock(pointer, blocking ? 1 : 0, errbuf);
      setNonBlockCheck(rc);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public void close() {
    readLock.lock();
    try {
      NativeMappings.pcap_close(pointer);
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public <T> T allocate(Class<T> cls) throws IllegalArgumentException {
    if (cls.isAssignableFrom(PacketHeader.class)) {
      return (T) new DefaultPacketHeader();
    } else if (cls.isAssignableFrom(PacketBuffer.class)) {
      return (T) new DefaultPacketBuffer();
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
      throw new BreakException("");
    } else {
      throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
    }
  }

  void dispatchCheck(int rc) throws ErrorException, BreakException {
    if (rc < 0) {
      if (rc == -1) {
        throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
      } else if (rc == -2) {
        throw new BreakException("");
      } else {
        throw new ErrorException("Generic error");
      }
    }
  }

  void nextExCheck(int rc, DefaultPacketHeader header, DefaultPacketBuffer buffer)
      throws TimeoutException, BreakException, ErrorException {
    if (rc == 0) {
      throw new TimeoutException("");
    } else if (rc == 1) {
      header.useMemoryFromReferece();
      header.ts.useMemoryFromReferece(header.reference);
      buffer.useMemoryFromReferece();
      buffer.setBuffer(header.captureLength());
    } else {
      if (rc == -2) {
        throw new BreakException("");
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

  void sendCheck(int rc) throws ErrorException {
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

  boolean swappedCheck(int swapped) {
    return swapped == NativeMappings.TRUE;
  }
}

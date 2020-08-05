/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.NativeTypes;
import java.foreign.Scope;
import java.foreign.memory.Callback;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeoutException;
import pcap.api.internal.foreign.bpf_header;
import pcap.api.internal.foreign.mapping.PcapMapping;
import pcap.api.internal.foreign.pcap_header;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.memory.Memories;
import pcap.common.memory.MemoryAllocator;
import pcap.common.util.Properties;
import pcap.common.util.Validate;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.exception.error.NotActivatedException;

/**
 * {@code Pcap} handle.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class Pcap implements pcap.spi.Pcap {

  private static final Logger LOGGER = LoggerFactory.getLogger(Pcap.class);
  private static final boolean BUFFER_POOLING = Properties.getBoolean("pcap.bufferPooling", true);
  private static final int BUFFER_POOL_SIZE = Properties.getInt("pcap.bufferPoolSize", 10);
  private static final int BUFFER_MAX_POOL_SIZE = Properties.getInt("pcap.bufferMaxPoolSize", 50);

  final Pointer<pcap_header.pcap> pcap;
  final Pointer<bpf_header.bpf_program> bpf_program;
  final Pointer<PcapStatus> pcap_stat;
  final int netmask;
  final int linktype;
  final int majorVersion;
  final int minorVersion;
  final boolean isSwapped;
  final MemoryAllocator allocator;
  private final Scope scope;

  boolean filterActivated;
  private Callback<PcapHandler> oneshotCallback;

  protected Pcap(Pointer<pcap_header.pcap> pcap) {
    this(pcap, 0xFFFFFF00);
  }

  protected Pcap(Pointer<pcap_header.pcap> pcap, int netmask) {
    this.scope = Scope.globalScope().fork();
    this.pcap = pcap;
    this.bpf_program = scope.allocate(LayoutType.ofStruct(bpf_header.bpf_program.class));
    this.pcap_stat = scope.allocate(LayoutType.ofStruct(PcapStatus.class));
    this.netmask = netmask;
    this.linktype = PcapMapping.MAPPING.pcap_datalink(pcap);
    this.filterActivated = false;
    int snapshot = PcapMapping.MAPPING.pcap_snapshot(pcap);
    this.majorVersion = PcapMapping.MAPPING.pcap_major_version(pcap);
    this.minorVersion = PcapMapping.MAPPING.pcap_minor_version(pcap);
    this.isSwapped = PcapMapping.MAPPING.pcap_is_swapped(pcap) == 1;
    if (BUFFER_POOLING) {
      LOGGER.debug(
          "Allocating pooled buffer with poolSize: %d, maxPoolSize: %d, capacity: %d",
          BUFFER_POOL_SIZE, BUFFER_MAX_POOL_SIZE, snapshot);
      this.allocator = Memories.directAllocator(BUFFER_POOL_SIZE, BUFFER_MAX_POOL_SIZE, snapshot);
    } else {
      this.allocator = Memories.directAllocator();
    }
  }

  /** {@inheritDoc} */
  @Override
  public Dumper dumpOpen(String file) throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Open dumper handler at new file on {}", file);
      }
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<pcap_header.pcap_dumper> pointer =
            PcapMapping.MAPPING.pcap_dump_open(pcap, scope.allocateCString(file));
        if (pointer == null || pointer.isNull()) {
          throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
        }
        return new PcapDumper(pointer);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public Dumper dumpOpenAppend(String file) throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Open dumper handler at existing file on {}", file);
      }
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<pcap_header.pcap_dumper> pointer =
            PcapMapping.MAPPING.pcap_dump_open_append(pcap, scope.allocateCString(file));
        if (pointer == null || pointer.isNull()) {
          throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
        }
        return new PcapDumper(pointer);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setFilter(String filter, boolean optimize) throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            "Set filter with expression {} and optimize is {}",
            filter,
            optimize ? "enabled" : "disabled");
      }
      try (Scope scope = Scope.globalScope().fork()) {
        if (PcapMapping.MAPPING.pcap_compile(
                pcap, bpf_program, scope.allocateCString(filter), optimize ? 1 : 0, netmask)
            != PcapMapping.OK) {
          throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
        }
      }
      if (PcapMapping.MAPPING.pcap_setfilter(pcap, bpf_program) != PcapMapping.OK) {
        throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
      }
      this.filterActivated = true;
    }
  }

  /** {@inheritDoc} */
  @Override
  public <T> void loop(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Looping {} packets.", count == -1 ? "infinite" : count);
        LOGGER.debug("Packets processed with {}.", handler.getClass().getName());
      }
      Callback<PcapHandler> callback =
          scope.allocateCallback(
              PcapHandler.class,
              (user, header, packets) -> {
                PacketHeader packetHeader = header.get().packetHeader();
                handler.gotPacket(
                    args,
                    packetHeader,
                    PcapPacketBuffer.fromReference(packets, packetHeader.captureLength()));
              });

      int result = PcapMapping.MAPPING.pcap_loop(pcap, count, callback, Pointer.ofNull());
      if (result == 0) {
        return;
      } else if (result == -2) {
        throw new BreakException("");
      } else {
        throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void nextEx(PacketBuffer packetBuffer, PacketHeader packetHeader)
      throws BreakException, TimeoutException, ErrorException {
    synchronized (PcapMapping.LOCK) {
      PcapPacketBuffer pcap_packet_buffer = (PcapPacketBuffer) packetBuffer;
      PcapPacketHeader.Impl pcap_packet_header = (PcapPacketHeader.Impl) packetHeader;

      if (pcap_packet_buffer.ptr == null) {
        return;
      }

      int result =
          PcapMapping.MAPPING.pcap_next_ex(pcap, pcap_packet_header.ptr, pcap_packet_buffer.ptr);

      if (result == 0) {
        throw new TimeoutException("");
      } else if (result == 1) {
        PcapPacketHeader pcapPacketHeader = pcap_packet_header.ptr.get().get();

        pcap_packet_header.timestamp = pcapPacketHeader.timestamp().timestamp();
        pcap_packet_header.captureLangth = pcapPacketHeader.captureLength();
        pcap_packet_header.length = pcapPacketHeader.length();
      } else {
        if (result == -2) {
          throw new BreakException("");
        } else {
          throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
        }
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public <T> void dispatch(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Dispatcing {} packets", count);
      }
      if (oneshotCallback == null) {
        oneshotCallback =
            scope.allocateCallback(
                PcapHandler.class,
                (user, header, packets) -> {
                  PacketHeader packetHeader = header.get().packetHeader();
                  handler.gotPacket(
                      args,
                      packetHeader,
                      PcapPacketBuffer.fromReference(packets, packetHeader.captureLength()));
                });
      }
      if (oneshotCallback != null) {
        int result =
            PcapMapping.MAPPING.pcap_dispatch(pcap, count, oneshotCallback, Pointer.ofNull());
        if (result < 0) {
          if (result == -1) {
            throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
          } else if (result == -2) {
            throw new BreakException("");
          } else {
            throw new ErrorException("Generic error.");
          }
        } else if (result == 0) {
          LOGGER.debug("No packets were read from a capture.");
        }
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public Status status() throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      int result = PcapMapping.MAPPING.pcap_stats(pcap, pcap_stat);
      if (result < 0) {
        throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
      }
      return pcap_stat.get().status();
    }
  }

  /** {@inheritDoc} */
  @Override
  public void breakLoop() {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Break looping packets.");
      }
      PcapMapping.MAPPING.pcap_breakloop(pcap);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void send(ByteBuffer buffer, int size) throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      int result = PcapMapping.MAPPING.pcap_sendpacket(pcap, Pointer.fromByteBuffer(buffer), size);
      if (result < 0) {
        throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void send(PacketBuffer buffer, int size) throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      Validate.notIllegalArgument(
          buffer.capacity() >= size,
          String.format(
              "buffer.capacity(%d) (expected: buffer.capacity(%d) >= size(%d)",
              buffer.capacity(), buffer.capacity(), size));

      int result = PcapMapping.MAPPING.pcap_sendpacket(pcap, ((PcapPacketBuffer) buffer).ref, size);
      if (result < 0) {
        throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
      }
    }
  }

  @Override
  public void send(PacketBuffer buffer) throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      Validate.notIllegalArgument(
          buffer.readerIndex() < buffer.writerIndex(),
          String.format(
              "readerIndex: %d, writerIndex: %d (expected: buffer.readerIndex(%d) < buffer.writerIndex(%d)",
              buffer.readerIndex(),
              buffer.writerIndex(),
              buffer.readerIndex(),
              buffer.writerIndex()));

      Pointer<Byte> pointer = ((PcapPacketBuffer) buffer).ref;
      int result =
          PcapMapping.MAPPING.pcap_sendpacket(
              pcap, pointer.offset(buffer.readerIndex()), buffer.writerIndex());
      if (result < 0) {
        throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setDirection(Direction direction) throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      int result = 0;
      if (Direction.PCAP_D_INOUT == direction) {
        result = PcapMapping.MAPPING.pcap_setdirection(pcap, 0);
      } else if (Direction.PCAP_D_IN == direction) {
        result = PcapMapping.MAPPING.pcap_setdirection(pcap, 1);
      } else if (Direction.PCAP_D_OUT == direction) {
        result = PcapMapping.MAPPING.pcap_setdirection(pcap, 2);
      }
      if (result != 0 && result < 0) {
        throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
      }
    }
  }

  @Override
  public boolean isSwapped() throws NotActivatedException {
    return isSwapped;
  }

  @Override
  public int majorVersion() {
    return majorVersion;
  }

  @Override
  public int minorVersion() {
    return minorVersion;
  }

  @Override
  public boolean getNonBlock() throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapMapping.ERRBUF_SIZE);
        int result = PcapMapping.MAPPING.pcap_getnonblock(pcap, errbuf);
        if (result < 0) {
          throw new ErrorException(Pointer.toString(errbuf));
        }
        return result == 1;
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setNonBlock(boolean blocking) throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapMapping.ERRBUF_SIZE);
        int result = PcapMapping.MAPPING.pcap_setnonblock(pcap, blocking ? 1 : 0, errbuf);
        if (result < 0) {
          throw new ErrorException(Pointer.toString(errbuf));
        }
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void close() {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Closing pcap handle.");
      }
      if (!bpf_program.isNull() && filterActivated) {
        PcapMapping.MAPPING.pcap_freecode(bpf_program);
      }
      if (!pcap.isNull()) {
        PcapMapping.MAPPING.pcap_close(pcap);
      }
      scope.close();
    }
  }

  /** {@inheritDoc} */
  @Override
  public <T> T allocate(Class<T> cls) {
    synchronized (PcapMapping.LOCK) {
      if (cls.isAssignableFrom(PacketBuffer.class)) {
        final Pointer<Pointer<Byte>> pcap_ptr_to_buffer =
            scope.allocate(NativeTypes.UINT8.pointer());
        return (T) PcapPacketBuffer.fromPointer(pcap_ptr_to_buffer, 0);
      } else if (cls.isAssignableFrom(PacketHeader.class)) {
        final Pointer<Pointer<PcapPacketHeader>> pcap_ptr_to_packet_header =
            scope.allocate(LayoutType.ofStruct(PcapPacketHeader.class).pointer());
        return (T)
            PcapPacketHeader.Impl.fromPointer(
                pcap_ptr_to_packet_header, new Timestamp.Impl(0, 0), 0, 0);
      }
      throw new IllegalArgumentException(
          "A class (" + cls + ") doesn't supported for this operation.");
    }
  }
}

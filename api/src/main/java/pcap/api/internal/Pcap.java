/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.NativeTypes;
import java.foreign.Scope;
import java.foreign.memory.Callback;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeoutException;
import pcap.api.handler.EventLoopHandler;
import pcap.api.internal.foreign.bpf_mapping;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.util.Validate;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;

/**
 * {@code Pcap} handle.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class Pcap implements pcap.spi.Pcap {

  private static final Logger LOGGER = LoggerFactory.getLogger(Pcap.class);
  final Pointer<pcap_mapping.pcap> pcap;
  final Pointer<bpf_mapping.bpf_program> bpf_program;
  final Pointer<PcapStatus> pcap_stat;
  final int netmask;
  final int linktype;
  private final Scope scope;
  private final Queue<Runnable> loopEvent = new LinkedBlockingQueue<>();
  boolean filterActivated;
  /** Event loop handler for {@link #loop(int, PacketHandler, Object)}. */
  private volatile boolean loopTerminated;

  private volatile int loopResult;

  public Pcap(Pointer<pcap_mapping.pcap> pcap) {
    this(pcap, 0xFFFFFF00);
  }

  public Pcap(Pointer<pcap_mapping.pcap> pcap, int netmask) {
    this.scope = Scope.globalScope().fork();
    this.pcap = pcap;
    this.bpf_program = scope.allocate(LayoutType.ofStruct(bpf_mapping.bpf_program.class));
    this.pcap_stat = scope.allocate(LayoutType.ofStruct(PcapStatus.class));
    this.netmask = netmask;
    this.linktype = PcapConstant.MAPPING.pcap_datalink(pcap);
    this.filterActivated = false;
  }

  /** {@inheritDoc} */
  @Override
  public Dumper dumpOpen(String file) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Open dumper handler at new file on {}", file);
      }
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<pcap_mapping.pcap_dumper> pointer =
            PcapConstant.MAPPING.pcap_dump_open(pcap, scope.allocateCString(file));
        if (pointer == null || pointer.isNull()) {
          throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
        }
        return new PcapDumper(pointer);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public Dumper dumpOpenAppend(String file) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Open dumper handler at existing file on {}", file);
      }
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<pcap_mapping.pcap_dumper> pointer =
            PcapConstant.MAPPING.pcap_dump_open_append(pcap, scope.allocateCString(file));
        if (pointer == null || pointer.isNull()) {
          throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
        }
        return new PcapDumper(pointer);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setFilter(String filter, boolean optimize) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            "Set filter with expression {} and optimize is {}",
            filter,
            optimize ? "enabled" : "disabled");
      }
      try (Scope scope = Scope.globalScope().fork()) {
        if (PcapConstant.MAPPING.pcap_compile(
                pcap, bpf_program, scope.allocateCString(filter), optimize ? 1 : 0, netmask)
            != PcapConstant.OK) {
          throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
        }
      }
      if (PcapConstant.MAPPING.pcap_setfilter(pcap, bpf_program) != PcapConstant.OK) {
        throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
      }
      this.filterActivated = true;
    }
  }

  /** {@inheritDoc} */
  @Override
  public <T> void loop(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (handler instanceof EventLoopHandler) {
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("Looping {} packets.", count == -1 ? "infinite" : count);
          LOGGER.debug("Packets processed with {} using event loop.", handler.getClass().getName());
        }
        Thread thread =
            new Thread(
                () -> {
                  Callback<PcapHandler> callback =
                      scope.allocateCallback(
                          PcapHandler.class,
                          (user, header, packets) -> {
                            PacketHeader packetHeader = header.get().packetHeader();
                            PacketBuffer packetBuffer =
                                PcapPacketBuffer.fromReference(
                                    packets, packetHeader.captureLength());
                            loopEvent.offer(
                                () -> {
                                  handler.gotPacket(args, packetHeader, packetBuffer);
                                });
                          });
                  int result =
                      PcapConstant.MAPPING.pcap_loop(pcap, count, callback, Pointer.ofNull());
                  loopTerminated = true;
                  Pcap.this.loopResult = result;
                },
                Pcap.class.getName() + ":EventLoop-0");
        thread.start();

        for (; ; ) {
          if (!loopTerminated) {
            Runnable runnable = loopEvent.poll();
            if (runnable != null) {
              runnable.run();
            }
          } else {
            // wait till all event processed
            Runnable runnable = loopEvent.poll();
            while (runnable != null) {
              runnable.run();
              runnable = loopEvent.poll();
            }
            if (loopResult == 0) {
              break;
            } else if (loopResult == -2) {
              throw new BreakException("");
            } else {
              throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
            }
          }
        }
      } else {
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

        int result = PcapConstant.MAPPING.pcap_loop(pcap, count, callback, Pointer.ofNull());
        if (result == 0) {
          return;
        } else if (result == -2) {
          throw new BreakException("");
        } else {
          throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
        }
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void nextEx(PacketBuffer packetBuffer, PacketHeader packetHeader)
      throws BreakException, TimeoutException, ErrorException {
    synchronized (PcapConstant.LOCK) {
      PcapPacketHeader.Impl pcap_packet_header = (PcapPacketHeader.Impl) packetHeader;
      PcapPacketBuffer pcap_packet_buffer = (PcapPacketBuffer) packetBuffer;

      int result =
          PcapConstant.MAPPING.pcap_next_ex(pcap, pcap_packet_header.ptr, pcap_packet_buffer.ptr);

      if (result == 0) {
        throw new TimeoutException("");
      } else if (result == 1) {
        PcapPacketHeader pcapPacketHeader = pcap_packet_header.ptr.get().get();
        Pointer<Byte> pointer = pcap_packet_buffer.ptr.get();

        pcap_packet_header.timestamp = pcapPacketHeader.timestamp().timestamp();
        pcap_packet_header.captureLangth = pcapPacketHeader.captureLength();
        pcap_packet_header.length = pcapPacketHeader.length();
        pcap_packet_buffer.buffer = pointer.asDirectByteBuffer(pcapPacketHeader.captureLength());
      } else {
        if (result == -2) {
          throw new BreakException("");
        } else {
          throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
        }
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public <T> void dispatch(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Dispatcing {} packets", count);
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
      int result = PcapConstant.MAPPING.pcap_dispatch(pcap, count, callback, Pointer.ofNull());
      if (result < 0) {
        if (result == -1) {
          throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
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

  /** {@inheritDoc} */
  @Override
  public Status status() throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      int result = PcapConstant.MAPPING.pcap_stats(pcap, pcap_stat);
      if (result < 0) {
        throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
      }
      return pcap_stat.get().status();
    }
  }

  /** {@inheritDoc} */
  @Override
  public void breakLoop() {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Break looping packets.");
      }
      PcapConstant.MAPPING.pcap_breakloop(pcap);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void send(ByteBuffer buffer, int size) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      int result = PcapConstant.MAPPING.pcap_sendpacket(pcap, Pointer.fromByteBuffer(buffer), size);
      if (result < 0) {
        throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void send(PacketBuffer buffer, int size) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      Validate.notIllegalArgument(
          buffer.capacity() >= size,
          String.format(
              "buffer.capacity(%d) (expected: buffer.capacity(%d) >= size(%d)",
              buffer.capacity(), buffer.capacity(), size));
      ByteBuffer byteBuffer = buffer.buffer();
      int result =
          PcapConstant.MAPPING.pcap_sendpacket(pcap, Pointer.fromByteBuffer(byteBuffer), size);
      if (result < 0) {
        throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setDirection(Direction direction) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      int result = 0;
      if (Direction.PCAP_D_INOUT == direction) {
        result = PcapConstant.MAPPING.pcap_setdirection(pcap, 0);
      } else if (Direction.PCAP_D_IN == direction) {
        result = PcapConstant.MAPPING.pcap_setdirection(pcap, 1);
      } else if (Direction.PCAP_D_OUT == direction) {
        result = PcapConstant.MAPPING.pcap_setdirection(pcap, 2);
      }
      if (result != 0 && result < 0) {
        throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setNonBlock(boolean blocking) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapConstant.ERRBUF_SIZE);
        int result = PcapConstant.MAPPING.pcap_setnonblock(pcap, blocking ? 1 : 0, errbuf);
        if (result < 0) {
          throw new ErrorException(Pointer.toString(errbuf));
        }
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void close() {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Closing pcap handle.");
      }
      if (!bpf_program.isNull() && filterActivated) {
        PcapConstant.MAPPING.pcap_freecode(bpf_program);
      }
      if (!pcap.isNull()) {
        PcapConstant.MAPPING.pcap_close(pcap);
      }
      scope.close();
    }
  }

  /** {@inheritDoc} */
  @Override
  public <T> T allocate(Class<T> cls) {
    synchronized (PcapConstant.LOCK) {
      final Pointer<Pointer<PcapPacketHeader>> pcap_ptr_to_packet_header =
          scope.allocate(LayoutType.ofStruct(PcapPacketHeader.class).pointer());
      final Pointer<Pointer<Byte>> pcap_ptr_to_buffer = scope.allocate(NativeTypes.UINT8.pointer());
      if (cls.isAssignableFrom(PacketBuffer.class)) {
        return (T) PcapPacketBuffer.fromPointer(pcap_ptr_to_buffer, 0);
      } else if (cls.isAssignableFrom(PacketHeader.class)) {
        return (T)
            PcapPacketHeader.Impl.fromPointer(
                pcap_ptr_to_packet_header, new Timestamp.Impl(0, 0), 0, 0);
      }
      throw new IllegalArgumentException(
          "A class (" + cls + ") doesn't supported for this operation.");
    }
  }
}

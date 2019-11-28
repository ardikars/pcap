/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Callback;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;
import pcap.api.PcapLive;
import pcap.api.PcapOffline;
import pcap.api.internal.foreign.bpf_mapping;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
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

  boolean filterActivated;

  public Pcap(Pointer<pcap_mapping.pcap> pcap) {
    this(pcap, 0xFFFFFF00);
  }

  public Pcap(Pointer<pcap_mapping.pcap> pcap, int netmask) {
    this.pcap = pcap;
    this.bpf_program =
        PcapConstant.SCOPE.allocate(LayoutType.ofStruct(bpf_mapping.bpf_program.class));
    this.pcap_stat = PcapConstant.SCOPE.allocate(LayoutType.ofStruct(PcapStatus.class));
    this.netmask = netmask;
    this.linktype = PcapConstant.MAPPING.pcap_datalink(pcap);
    this.filterActivated = false;
  }

  /**
   * Open {@link Dumper} handler.
   *
   * @param file location of capture file will saved.
   * @return returns {@code Pcap} {@link Dumper} handle.
   * @throws ErrorException
   */
  @Override
  public Dumper dumpOpen(String file) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Open dumper handler at new file on {}", file);
      }
      Pointer<pcap_mapping.pcap_dumper> pointer =
          PcapConstant.MAPPING.pcap_dump_open(pcap, PcapConstant.SCOPE.allocateCString(file));
      if (pointer == null || pointer.isNull()) {
        throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
      }
      return new PcapDumper(pointer);
    }
  }

  /**
   * Append packet buffer on existing {@code pcap} file.
   *
   * @param file location of saved file.
   * @return returns {@code Pcap} {@link Dumper} handle.
   * @throws ErrorException generic error.
   */
  @Override
  public Dumper dumpOpenAppend(String file) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Open dumper handler at existing file on {}", file);
      }
      Pointer<pcap_mapping.pcap_dumper> pointer =
          PcapConstant.MAPPING.pcap_dump_open_append(
              pcap, PcapConstant.SCOPE.allocateCString(file));
      if (pointer == null || pointer.isNull()) {
        throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
      }
      return new PcapDumper(pointer);
    }
  }

  /**
   * BPF packet filter.
   *
   * @param filter filter expression.
   * @param optimize {@code true} for optimized filter, {@code false} otherwise.
   * @throws ErrorException generic error.
   */
  @Override
  public void setFilter(String filter, boolean optimize) throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            "Set filter with expression {} and optimize is {}",
            filter,
            optimize ? "enabled" : "disabled");
      }
      if (PcapConstant.MAPPING.pcap_compile(
              pcap,
              bpf_program,
              PcapConstant.SCOPE.allocateCString(filter),
              optimize ? 1 : 0,
              netmask)
          != PcapConstant.OK) {
        throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
      }
      if (PcapConstant.MAPPING.pcap_setfilter(pcap, bpf_program) != PcapConstant.OK) {
        throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
      }
      this.filterActivated = true;
    }
  }

  /**
   * Process packets from a live {@link PcapLive} or {@link PcapOffline}.
   *
   * @param count maximum number of packets to process before returning. A value of -1 or 0 for cnt
   *     is equivalent to infinity, so that packets are processed until another ending condition
   *     occurs.
   * @param handler {@link PacketHandler} callback function.
   * @param args user args.
   * @param <T> args type.
   * @throws BreakException {@link Pcap#breakLoop()} is called.
   * @throws ErrorException Generic error.
   */
  @Override
  public <T> void loop(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Looping {} packets", count);
      }
      Callback<PcapHandler> callback =
          PcapConstant.SCOPE.allocateCallback(
              PcapHandler.class,
              (user, header, packets) -> {
                PacketHeader packetHeader = header.get().packetHeader();
                handler.gotPacket(
                    args, packetHeader, new PcapBuffer(packets, packetHeader.captureLength()));
              });
      int result = PcapConstant.MAPPING.pcap_loop(pcap, count, callback, Pointer.ofNull());
      if (result == 0) {
        return;
      } else if (result == -2) {
        throw new BreakException("");
      } else {
        throw new ErrorException("Generic error.");
      }
    }
  }

  /**
   * Represent packet statistics from the start of the run to the time of the call.
   *
   * <p>Supported only on live captures, not on {@link PcapOffline}; no statistics are stored in
   * {@link PcapOffline} so no statistics are available when reading from a {@link PcapOffline}
   *
   * @return returns {@link Status} on success.
   * @throws ErrorException There is an error or if this {@link Pcap} doesn't support packet
   *     statistics.
   */
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

  /**
   * Force a {@link Pcap#loop(int, PacketHandler, Object)} call to return And throw {@link
   * BreakException} on {@link Pcap#loop(int, PacketHandler, Object)}.
   */
  @Override
  public void breakLoop() {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Break looping packets.");
      }
      PcapConstant.MAPPING.pcap_breakloop(pcap);
    }
  }

  /**
   * Sends a raw packet through the network interface.
   *
   * @param buffer the data of the packet, including the link-layer header.
   * @throws ErrorException generic error.
   */
  public void send(ByteBuffer buffer) throws ErrorException {
    send(buffer, buffer.capacity());
  }

  /**
   * Sends a raw packet through the network interface.
   *
   * @param buffer the data of the packet, including the link-layer header.
   * @param size the number of bytes in the packet.
   * @throws ErrorException generic error.
   */
  @Override
  public void send(ByteBuffer buffer, int size) throws ErrorException {
    int result = PcapConstant.MAPPING.pcap_sendpacket(pcap, Pointer.fromByteBuffer(buffer), size);
    if (result < 0) {
      throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pcap)));
    }
  }

  /** Close {@link PcapLive} or {@link PcapOffline}. Note: BPF handle will closed automaticly. */
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
    }
  }
}

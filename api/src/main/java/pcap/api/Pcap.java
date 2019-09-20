/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.memory.Callback;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import pcap.api.internal.*;
import pcap.api.internal.foreign.bpf_mapping;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Dumper;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;
import pcap.spi.Status;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Pcap {

  private static final Logger LOGGER = LoggerFactory.getLogger(Pcap.class);

  final Pointer<pcap_mapping.pcap> pcap;
  final Pointer<bpf_mapping.bpf_program> bpf_program;
  final Pointer<PcapStat> pcap_stat;
  final int netmask;
  final int linktype;

  boolean filterActivated;

  Pcap(Pointer<pcap_mapping.pcap> pcap) {
    this(pcap, 0xFFFFFF00);
  }

  Pcap(Pointer<pcap_mapping.pcap> pcap, int netmask) {
    this.pcap = pcap;
    this.bpf_program =
        PcapConstant.SCOPE.allocate(LayoutType.ofStruct(bpf_mapping.bpf_program.class));
    this.pcap_stat = PcapConstant.SCOPE.allocate(LayoutType.ofStruct(PcapStat.class));
    this.netmask = netmask;
    this.linktype = PcapConstant.MAPPING.pcap_datalink(pcap);
    this.filterActivated = false;
  }

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

  public <T> void loop(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.info("Looping {} packets", count);
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

  public Status status() {
    synchronized (PcapConstant.LOCK) {
      int result = PcapConstant.MAPPING.pcap_stats(pcap, pcap_stat);
      return pcap_stat.get().status();
    }
  }

  public void breakLoop() {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Break looping packets.");
      }
      PcapConstant.MAPPING.pcap_breakloop(pcap);
    }
  }

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

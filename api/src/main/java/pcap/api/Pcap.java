/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.Libraries;
import java.foreign.Library;
import java.foreign.Scope;
import java.foreign.memory.Callback;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.PcapBuffer;
import pcap.api.internal.PcapDumper;
import pcap.api.internal.PcapHandler;
import pcap.api.internal.PcapStat;
import pcap.api.internal.exception.BreakException;
import pcap.api.internal.exception.PcapErrorException;
import pcap.api.internal.foreign.bpf_mapping;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.util.Platforms;
import pcap.spi.Dumper;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;
import pcap.spi.Status;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Pcap {

  private static final Logger LOGGER = LoggerFactory.getLogger(Pcap.class);

  public static final int OK = 0;

  public static final Object LOCK = new Object();

  public static final int ERRBUF_SIZE = 256;

  public static final pcap_mapping MAPPING;

  public static final Scope SCOPE;

  final Pointer<pcap_mapping.pcap> pcap;
  final Pointer<bpf_mapping.bpf_program> bpf_program;
  final Pointer<PcapStat> pcap_stat;
  final int netmask;
  final int linktype;

  boolean filterActivated;

  public Pcap(Pointer<pcap_mapping.pcap> pcap) {
    this(pcap, 0xFFFFFF00);
  }

  public Pcap(Pointer<pcap_mapping.pcap> pcap, int netmask) {
    this.pcap = pcap;
    this.bpf_program = SCOPE.allocate(LayoutType.ofStruct(bpf_mapping.bpf_program.class));
    this.pcap_stat = SCOPE.allocate(LayoutType.ofStruct(PcapStat.class));
    this.netmask = netmask;
    this.linktype = MAPPING.pcap_datalink(pcap);
    this.filterActivated = false;
  }

  public Dumper dumpOpen(String file) throws PcapErrorException {
    synchronized (LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Open dumper handler at new file on {}", file);
      }
      Pointer<pcap_mapping.pcap_dumper> pointer =
          MAPPING.pcap_dump_open(pcap, SCOPE.allocateCString(file));
      if (pointer == null || pointer.isNull()) {
        throw new PcapErrorException(Pointer.toString(MAPPING.pcap_geterr(pcap)));
      }
      return new PcapDumper(pointer);
    }
  }

  public Dumper dumpOpenAppend(String file) throws PcapErrorException {
    synchronized (LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Open dumper handler at existing file on {}", file);
      }
      Pointer<pcap_mapping.pcap_dumper> pointer =
          MAPPING.pcap_dump_open_append(pcap, SCOPE.allocateCString(file));
      if (pointer == null || pointer.isNull()) {
        throw new PcapErrorException(Pointer.toString(MAPPING.pcap_geterr(pcap)));
      }
      return new PcapDumper(pointer);
    }
  }

  public void setFilter(String filter, boolean optimize) throws PcapErrorException {
    synchronized (LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            "Set filter with expression {} and optimize is {}",
            filter,
            optimize ? "enabled" : "disabled");
      }
      if (MAPPING.pcap_compile(
              pcap, bpf_program, SCOPE.allocateCString(filter), optimize ? 1 : 0, netmask)
          != OK) {
        throw new PcapErrorException(Pointer.toString(MAPPING.pcap_geterr(pcap)));
      }
      if (MAPPING.pcap_setfilter(pcap, bpf_program) != OK) {
        throw new PcapErrorException(Pointer.toString(MAPPING.pcap_geterr(pcap)));
      }
      this.filterActivated = true;
    }
  }

  public <T> void loop(int count, PacketHandler<T> handler, T args)
      throws BreakException, PcapErrorException {
    synchronized (LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.info("Looping {} packets", count);
      }
      Callback<PcapHandler> callback =
          SCOPE.allocateCallback(
              PcapHandler.class,
              (user, header, packets) -> {
                PacketHeader packetHeader = header.get().packetHeader();
                handler.gotPacket(
                    args, packetHeader, new PcapBuffer(packets, packetHeader.captureLength()));
              });
      int result = MAPPING.pcap_loop(pcap, count, callback, Pointer.ofNull());
      if (result == 0) {
        return;
      } else if (result == -2) {
        throw new BreakException("");
      } else {
        throw new PcapErrorException("Generic error.");
      }
    }
  }

  public Status status() {
    synchronized (LOCK) {
      int result = MAPPING.pcap_stats(pcap, pcap_stat);
      return pcap_stat.get().status();
    }
  }

  public void breakLoop() {
    synchronized (LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Break looping packets.");
      }
      MAPPING.pcap_breakloop(pcap);
    }
  }

  public void close() {
    synchronized (LOCK) {
      if (!bpf_program.isNull() && filterActivated) {
        MAPPING.pcap_freecode(bpf_program);
      }
      if (!pcap.isNull()) {
        MAPPING.pcap_close(pcap);
      }
    }
  }

  static {
    MethodHandles.Lookup lookup = MethodHandles.lookup();
    Library library = Libraries.loadLibrary(lookup, Platforms.isWindows() ? "wpcap" : "pcap");
    MAPPING = Libraries.bind(pcap_mapping.class, library);
    SCOPE = Libraries.libraryScope(MAPPING);
  }
}

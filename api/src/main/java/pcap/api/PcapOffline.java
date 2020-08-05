/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.NativeTypes;
import java.foreign.Scope;
import java.foreign.memory.Pointer;
import java.io.File;
import pcap.api.internal.Pcap;
import pcap.api.internal.UnixPcap;
import pcap.api.internal.WinPcap;
import pcap.api.internal.foreign.mapping.PcapMapping;
import pcap.api.internal.foreign.pcap_header;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.util.Platforms;
import pcap.spi.exception.ErrorException;

@Inclubating
public class PcapOffline extends Pcaps {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapOffline.class);

  private final String file; // not null
  private final PcapOfflineOptions options; // nullable

  @Deprecated
  public PcapOffline(String file) {
    this(file, new PcapOfflineOptions());
  }

  @Deprecated
  public PcapOffline(String file, PcapOfflineOptions options) {
    this.file = file;
    this.options = options;
  }

  public PcapOffline(File file) {
    this(file, new PcapOfflineOptions());
  }

  public PcapOffline(File file, PcapOfflineOptions options) {
    this.file = file.getAbsolutePath();
    this.options = options;
  }

  @Override
  Pcap open() throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapMapping.ERRBUF_SIZE);
        Pointer<pcap_header.pcap> pointer;
        if (options.timestampPrecision() == null) {
          if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Opening file: {}", file);
          }
          pointer = PcapMapping.MAPPING.pcap_open_offline(scope.allocateCString(file), errbuf);
        } else {
          if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                "Opening file ({}) with timestamp precision ({})",
                file,
                options.timestampPrecision().value());
          }
          pointer =
              PcapMapping.MAPPING.pcap_open_offline_with_tstamp_precision(
                  scope.allocateCString(file), options.timestampPrecision().value(), errbuf);
        }
        nullCheck(pointer, errbuf);
        if (Platforms.isWindows()) {
          return new WinPcap(pointer);
        }
        return new UnixPcap(pointer);
      }
    }
  }

  void nullCheck(Pointer<pcap_header.pcap> pointer, Pointer<Byte> errbuf) {
    if (pointer == null || pointer.isNull()) {
      throw new IllegalStateException(Pointer.toString(errbuf));
    }
  }
}

package pcap.api;

import java.foreign.NativeTypes;
import java.foreign.memory.Pointer;

import pcap.api.internal.Pcap;
import pcap.api.internal.PcapConstant;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Timestamp;
import pcap.spi.exception.ErrorException;

@Inclubating
public class PcapOffline extends Pcaps {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapOffline.class);

  private Timestamp.Precision timestampPrecision; // nullable
  private String file; // not null

  public PcapOffline(String file) {
    this(null, file);
  }

  public PcapOffline(Timestamp.Precision timestampPrecision, String file) {
    this.timestampPrecision = timestampPrecision;
    this.file = file;
  }

  public PcapOffline timestampPrecision(Timestamp.Precision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
    return this;
  }

  @Override
  Pcap open() throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      Pointer<Byte> errbuf =
          PcapConstant.SCOPE.allocate(NativeTypes.INT8, PcapConstant.ERRBUF_SIZE);
      Pointer<pcap_mapping.pcap> pointer;
      if (timestampPrecision == null) {
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("Opening file: {}", file);
        }
        pointer =
            PcapConstant.MAPPING.pcap_open_offline(
                PcapConstant.SCOPE.allocateCString(file), errbuf);
      } else {
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug(
              "Opening file ({}) with timestamp precision ({})", file, timestampPrecision.value());
        }
        pointer =
            PcapConstant.MAPPING.pcap_open_offline_with_tstamp_precision(
                PcapConstant.SCOPE.allocateCString(file), timestampPrecision.value(), errbuf);
      }
      if (pointer == null || pointer.isNull()) {
        throw new ErrorException(Pointer.toString(errbuf));
      }
      return new Pcap(pointer);
    }
  }
}

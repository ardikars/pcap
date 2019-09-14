/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.NativeTypes;
import java.foreign.memory.Pointer;
import pcap.api.internal.PcapInterface;
import pcap.api.internal.exception.ActivatedException;
import pcap.api.internal.exception.CanSetTStampTypeException;
import pcap.api.internal.exception.InterfaceNotUpException;
import pcap.api.internal.exception.NoSuchDeviceException;
import pcap.api.internal.exception.PcapErrorException;
import pcap.api.internal.exception.PermissionDeniedException;
import pcap.api.internal.exception.PromiscPermissionDeniedException;
import pcap.api.internal.exception.RfmonNotSupportedException;
import pcap.api.internal.exception.TStampPrecisionNotSupportedException;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Interface;
import pcap.spi.Timestamp;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
abstract class AbstractBootstrap {

  static final Logger LOGGER = LoggerFactory.getLogger(AbstractBootstrap.class);

  private final boolean offline;
  protected String file;
  protected Interface source;
  protected int snaplen;
  protected boolean promiscuous;
  protected boolean rfmon;
  protected int timeout;
  protected Timestamp.Type timestampType;
  protected boolean immediateMode;
  protected int bufferSize;

  /** Offline and live handle */
  protected Timestamp.Precision timestampPrecision;

  AbstractBootstrap(boolean offline) {
    this.offline = offline;
  }

  public abstract Pcap open() throws Exception;

  protected Pcap openHandle()
      throws PcapErrorException, CanSetTStampTypeException, PermissionDeniedException,
          PromiscPermissionDeniedException, RfmonNotSupportedException, NoSuchDeviceException,
          TStampPrecisionNotSupportedException, InterfaceNotUpException, ActivatedException {
    synchronized (Pcap.LOCK) {
      if (offline) {
        Pointer<Byte> errbuf = Pcap.SCOPE.allocate(NativeTypes.INT8, Pcap.ERRBUF_SIZE);
        Pointer<pcap_mapping.pcap> pointer;
        if (timestampPrecision == null) {
          LOGGER.debug("Opening file: {}", file);
          pointer = Pcap.MAPPING.pcap_open_offline(Pcap.SCOPE.allocateCString(file), errbuf);
        } else {
          LOGGER.debug(
              "Opening file ({}) with timestamp precision ({})", file, timestampPrecision.value());
          pointer =
              Pcap.MAPPING.pcap_open_offline_with_tstamp_precision(
                  Pcap.SCOPE.allocateCString(file), timestampPrecision.value(), errbuf);
        }
        if (pointer == null || pointer.isNull()) {
          throw new PcapErrorException(Pointer.toString(errbuf));
        }
        return new Pcap(pointer);
      } else {
        PcapInterface pcapInterface;
        if (source == null) {
          pcapInterface = (PcapInterface) PcapInterface.lookup();
        } else {
          pcapInterface = (PcapInterface) source;
        }
        if (timestampType == null && timestampPrecision == null) {
          return pcapInterface.openLive(
              snaplen == 0 ? 65535 : snaplen, promiscuous, timeout == 0 ? 2000 : timeout);
        } else if (timestampType == null || timestampPrecision == null) {
          return pcapInterface.openLive();
        } else {
          return pcapInterface.openLive(
              snaplen == 0 ? 65535 : snaplen,
              promiscuous,
              rfmon,
              timeout == 0 ? 2000 : timeout,
              timestampType == null ? Timestamp.Type.HOST : timestampType,
              immediateMode,
              bufferSize,
              timestampPrecision == null ? Timestamp.Precision.MICRO : timestampPrecision);
        }
      }
    }
  }
}

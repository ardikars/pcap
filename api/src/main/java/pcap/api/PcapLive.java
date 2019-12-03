/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.NativeTypes;
import java.foreign.memory.Pointer;
import java.net.Inet4Address;
import pcap.api.internal.Pcap;
import pcap.api.internal.PcapConstant;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Interface;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.exception.warn.PromiscuousModeNotSupported;

@Inclubating
public class PcapLive extends Pcaps {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapLive.class);

  private Interface source; // not null
  private PcapLiveOptions options;

  public PcapLive(Interface source) {
    this(source, new PcapLiveOptions());
  }

  public PcapLive(Interface source, PcapLiveOptions options) {
    this.source = source;
    this.options = options;
  }

  @Override
  Pcap open()
      throws ErrorException, ActivatedException, InterfaceNotSupportTimestampTypeException,
          NoSuchDeviceException, PermissionDeniedException, PromiscuousModeNotSupported,
          PromiscuousModePermissionDeniedException, RadioFrequencyModeNotSupportedException,
          InterfaceNotUpException, TimestampPrecisionNotSupportedException {
    synchronized (PcapConstant.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Opening live handler on {}.", source.name());
      }
      Pointer<Byte> errbuf =
          PcapConstant.SCOPE.allocate(NativeTypes.INT8, PcapConstant.ERRBUF_SIZE);
      Pointer<pcap_mapping.pcap> pointer =
          PcapConstant.MAPPING.pcap_create(
              PcapConstant.SCOPE.allocateCString(source.name()), errbuf);
      if (pointer == null || pointer.isNull()) {
        throw new ErrorException(Pointer.toString(errbuf));
      }
      if (PcapConstant.MAPPING.pcap_set_snaplen(pointer, options.snapshotLength())
          != PcapConstant.OK) {
        throw new ActivatedException("Error occurred when set snapshot length.");
      }
      if (PcapConstant.MAPPING.pcap_set_promisc(pointer, options.isPromiscuous() ? 1 : 0)
          != PcapConstant.OK) {
        throw new ActivatedException("Error occurred when set promiscuous mode.");
      }
      int result = PcapConstant.MAPPING.pcap_can_set_rfmon(pointer);
      if (result == PcapConstant.OK) {
        if (PcapConstant.MAPPING.pcap_set_rfmon(pointer, options.isRfmon() ? 1 : 0) != 0) {
          throw new ActivatedException("Error occurred when set radio frequency monitor mode.");
        }
      } else if (result == -4) {
        throw new ActivatedException("Error occurred when set radio frequency monitor mode.");
      } else if (result == -5) {
        throw new NoSuchDeviceException("Error occurred when set radio frequency monitor mode.");
      } else {
        if (result == -1) {
          throw new ErrorException(Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pointer)));
        } else {
          if (result < 0) {
            throw new ErrorException(
                Pointer.toString(PcapConstant.MAPPING.pcap_statustostr(result)));
          } else {
            LOGGER.warn(
                "pcap_can_set_rfmon: {}",
                Pointer.toString(PcapConstant.MAPPING.pcap_statustostr(result)));
          }
        }
      }
      if (PcapConstant.MAPPING.pcap_set_timeout(pointer, options.timeout()) != PcapConstant.OK) {
        throw new ActivatedException("Error occurred when set timeout.");
      }
      if (options.timestampType() != null) {
        result =
            PcapConstant.MAPPING.pcap_set_tstamp_type(pointer, options.timestampType().value());
        if (result == -4) {
          throw new ActivatedException("Error occurred when set timestamp type.");
        } else if (result == 3) {
          LOGGER.warn(
              "pcap_set_tstamp_type: {}",
              Pointer.toString(PcapConstant.MAPPING.pcap_statustostr(result)));
        } else if (result == -10) {
          throw new InterfaceNotSupportTimestampTypeException(
              "Error occurred when set timestamp type.");
        }
      }
      if (PcapConstant.MAPPING.pcap_set_immediate_mode(pointer, options.isImmediate() ? 1 : 0)
          != PcapConstant.OK) {
        throw new ActivatedException("Error occurred when set immediate mode.");
      }
      if (PcapConstant.MAPPING.pcap_set_buffer_size(pointer, options.bufferSize())
          != PcapConstant.OK) {
        throw new ActivatedException("Error occurred when set buffer size.");
      }
      result =
          PcapConstant.MAPPING.pcap_set_tstamp_precision(
              pointer, options.timestampPrecision().value());
      if (result == -12) {
        throw new TimestampPrecisionNotSupportedException(
            "Error occurred when set timestamp procision.");
      } else if (result == -4) {
        throw new ActivatedException("Error occurred when set timestamp procision.");
      }
      result = PcapConstant.MAPPING.pcap_activate(pointer);
      if (result == 2) {
        throw new PromiscuousModeNotSupported(
            Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pointer)));
      } else if (result == 3) {
        LOGGER.warn(
            "pcap_activate: {}", Pointer.toString(PcapConstant.MAPPING.pcap_statustostr(result)));
      } else if (result == 1) {
        LOGGER.warn(
            "pcap_activate: {}", Pointer.toString(PcapConstant.MAPPING.pcap_statustostr(result)));
      } else if (result == -4) {
        throw new ActivatedException("Error occurred when activate a handle.");
      } else if (result == -5) {
        throw new NoSuchDeviceException(
            Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pointer)));
      } else if (result == -8) {
        throw new PermissionDeniedException(
            Pointer.toString(PcapConstant.MAPPING.pcap_geterr(pointer)));
      } else if (result == -11) {
        throw new PromiscuousModePermissionDeniedException(
            "Error occurred when activate a handle.");
      } else if (result == -6) {
        throw new RadioFrequencyModeNotSupportedException("Error occurred when activate a handle.");
      } else if (result == -9) {
        throw new InterfaceNotUpException("Error occurred when activate a handle.");
      }
      int netmask = 0xFFFFFF00;
      if (source.addresses().netmask() instanceof Inet4Address) {
        byte[] address = source.addresses().netmask().getAddress();
        for (int i = 0; i < 4; i++) {
          netmask |= (address[i] & 0xff) << (3 - i) * 8;
        }
      }
      return new Pcap(pointer, netmask);
    }
  }
}

/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.NativeTypes;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.net.Inet4Address;
import java.util.Iterator;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import pcap.api.Pcap;
import pcap.api.internal.exception.ActivatedException;
import pcap.api.internal.exception.CanSetTStampTypeException;
import pcap.api.internal.exception.InterfaceNotUpException;
import pcap.api.internal.exception.NoSuchDeviceException;
import pcap.api.internal.exception.PcapErrorException;
import pcap.api.internal.exception.PermissionDeniedException;
import pcap.api.internal.exception.PromiscNotSupported;
import pcap.api.internal.exception.PromiscPermissionDeniedException;
import pcap.api.internal.exception.RfmonNotSupportedException;
import pcap.api.internal.exception.TStampPrecisionNotSupportedException;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.api.internal.util.PcapInterfaceIterator;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Timestamp;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class PcapInterface implements Interface {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapInterface.class);

  /** Interface is loopback. */
  private static final int PCAP_IF_LOOPBACK = 0x00000001;

  /** Interface is up. */
  private static final int PCAP_IF_UP = 0x00000002;

  /** Interface is running. */
  private static final int PCAP_IF_RUNNING = 0x00000004;

  Interface next;
  String name;
  String description;
  Address addresses;
  int flags;
  boolean loopback;
  boolean up;
  boolean running;

  PcapInterface() {
    //
  }

  PcapInterface(pcap_mapping.pcap_if pcap_if) {
    this.name = Pointer.toString(pcap_if.name$get());
    this.description = Pointer.toString(pcap_if.description$get());
    this.flags = pcap_if.flags$get();
    this.addresses = new PcapAddress(pcap_if.addresses$get().get());
    if (!pcap_if.next$get().isNull()) {
      this.next = new PcapInterface(pcap_if.next$get().get());
    }
    this.loopback = (this.flags & PCAP_IF_LOOPBACK) != 0;
    this.up = (this.flags & PCAP_IF_UP) != 0;
    this.running = (this.flags & PCAP_IF_RUNNING) != 0;
  }

  @Override
  public Interface next() {
    return next;
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public String description() {
    return description;
  }

  @Override
  public Address addresses() {
    return addresses;
  }

  public int flags() {
    return flags;
  }

  /**
   * Is loopback interface?
   *
   * @return true if loopback interface, false otherwise.
   */
  public boolean isLoopback() {
    return loopback;
  }

  /**
   * Is interface is up?
   *
   * @return true if interface is up, false otherwise.
   */
  public boolean isUp() {
    return up;
  }

  /**
   * Is interface is running?
   *
   * @return true if interface is running, false otherwise.
   */
  public boolean isRunning() {
    return running;
  }

  @Override
  public Iterator<Interface> iterator() {
    return new PcapInterfaceIterator(this);
  }

  @Override
  public String toString() {
    StringBuilder sb =
        new StringBuilder()
            .append("{\n")
            .append("\t\"name\": \"")
            .append(name)
            .append("\",\n")
            .append("\t\"description\": \"")
            .append(description)
            .append("\",\n")
            .append("\t\"flags\": \"")
            .append(flags)
            .append("\",\n")
            .append("\t\"isLoopback\": \"")
            .append(isLoopback())
            .append("\",\n")
            .append("\t\"isUp\": \"")
            .append(isUp())
            .append("\",\n")
            .append("\t\"isRunning\": \"")
            .append(isRunning())
            .append("\",\n")
            .append("\t\"addresses\": \n")
            .append("\t\t[\n")
            .append(
                StreamSupport.stream(addresses.spliterator(), false)
                    .map(
                        addr ->
                            new StringBuilder()
                                .append("\t\t\t{\n")
                                .append("\t\t\t\t\"address\": \"")
                                .append(addr.address())
                                .append("\",\n")
                                .append("\t\t\t\t\"netmask\": \"")
                                .append(addr.netmask())
                                .append("\",\n")
                                .append("\t\t\t\t\"broadcast\": \"")
                                .append(addr.broadcast())
                                .append("\",\n")
                                .append("\t\t\t\t\"destination\": \"")
                                .append(addr.destination())
                                .append("\"\n")
                                .append("\t\t\t}")
                                .toString())
                    .collect(Collectors.joining(",\n")))
            .append("\n\t\t]\n")
            .append("}");
    return sb.toString();
  }

  public static Interface findAll() throws PcapErrorException {
    synchronized (Pcap.LOCK) {
      Pointer<Pointer<pcap_mapping.pcap_if>> pointer =
          Pcap.SCOPE.allocate(LayoutType.ofStruct(pcap_mapping.pcap_if.class).pointer());
      Pointer<Byte> errbuf = Pcap.SCOPE.allocate(NativeTypes.INT8, Pcap.ERRBUF_SIZE);
      int result = Pcap.MAPPING.pcap_findalldevs(pointer, errbuf);
      if (result != Pcap.OK) {
        throw new PcapErrorException(Pointer.toString(errbuf));
      }
      pcap_mapping.pcap_if pcap_if = pointer.get().get();
      Interface devices = new PcapInterface(pcap_if);
      Pcap.MAPPING.pcap_freealldevs(pointer.get());
      return devices;
    }
  }

  public static Interface lookup() throws PcapErrorException {
    synchronized (Pcap.LOCK) {
      Pointer<Byte> errbuf = Pcap.SCOPE.allocate(NativeTypes.INT8, Pcap.ERRBUF_SIZE);
      Pointer<Byte> device = Pcap.MAPPING.pcap_lookupdev(errbuf);
      if (device == null || device.isNull()) {
        throw new PcapErrorException(Pointer.toString(errbuf));
      }
      String deviceName = Pointer.toString(device);
      Interface pcapInterface =
          StreamSupport.stream(findAll().spliterator(), false)
              .filter(iface -> deviceName.equals(iface.name()))
              .findFirst()
              .get();
      return pcapInterface;
    }
  }

  public Pcap openLive(
      int snaplen,
      boolean promiscuous,
      boolean rfmon,
      int timeout,
      Timestamp.Type tstampType,
      boolean immedateMode,
      int bufferSize,
      Timestamp.Precision tstampPrecision)
      throws PcapErrorException, ActivatedException, CanSetTStampTypeException,
          NoSuchDeviceException, PermissionDeniedException, PromiscPermissionDeniedException,
          RfmonNotSupportedException, InterfaceNotUpException,
          TStampPrecisionNotSupportedException {
    synchronized (Pcap.LOCK) {
      Pointer<Byte> errbuf = Pcap.SCOPE.allocate(NativeTypes.INT8, Pcap.ERRBUF_SIZE);
      Pointer<pcap_mapping.pcap> pointer =
          Pcap.MAPPING.pcap_create(Pcap.SCOPE.allocateCString(name), errbuf);
      if (pointer == null || pointer.isNull()) {
        throw new PcapErrorException(Pointer.toString(errbuf));
      }
      if (Pcap.MAPPING.pcap_set_snaplen(pointer, snaplen) != Pcap.OK) {
        throw new ActivatedException("Error occurred when set snapshot length.");
      }
      if (Pcap.MAPPING.pcap_set_promisc(pointer, promiscuous ? 1 : 0) != Pcap.OK) {
        throw new ActivatedException("Error occurred when set promiscuous mode.");
      }
      int result = Pcap.MAPPING.pcap_can_set_rfmon(pointer);
      if (result == Pcap.OK) {
        if (Pcap.MAPPING.pcap_set_rfmon(pointer, rfmon ? 1 : 0) != 0) {
          throw new ActivatedException("Error occurred when set radio frequency monitor mode.");
        }
      } else if (result == -4) {
        throw new ActivatedException("Error occurred when set radio frequency monitor mode.");
      } else if (result == -5) {
        throw new NoSuchDeviceException("Error occurred when set radio frequency monitor mode.");
      } else {
        if (result == -1) {
          throw new PcapErrorException(Pointer.toString(Pcap.MAPPING.pcap_geterr(pointer)));
        } else {
          if (result < 0) {
            throw new PcapErrorException(Pointer.toString(Pcap.MAPPING.pcap_statustostr(result)));
          } else {
            LOGGER.warn(Pointer.toString(Pcap.MAPPING.pcap_statustostr(result)));
          }
        }
      }
      if (Pcap.MAPPING.pcap_set_timeout(pointer, timeout) != Pcap.OK) {
        throw new ActivatedException("Error occurred when set timeout.");
      }
      result = Pcap.MAPPING.pcap_set_tstamp_type(pointer, tstampType.value());
      if (result == -4) {
        throw new ActivatedException("Error occurred when set timestamp type.");
      } else if (result == 3) {
        LOGGER.warn(Pointer.toString(Pcap.MAPPING.pcap_statustostr(result)));
        // throw new TStampTypeNotSupportedException("Error occurred when set timestamp type.");
      } else if (result == -10) {
        throw new CanSetTStampTypeException("Error occurred when set timestamp type.");
      }
      if (Pcap.MAPPING.pcap_set_immediate_mode(pointer, immedateMode ? 1 : 0) != Pcap.OK) {
        throw new ActivatedException("Error occurred when set immediate mode.");
      }
      if (Pcap.MAPPING.pcap_set_buffer_size(pointer, bufferSize) != Pcap.OK) {
        throw new ActivatedException("Error occurred when set buffer size.");
      }
      result = Pcap.MAPPING.pcap_set_tstamp_precision(pointer, tstampPrecision.value());
      if (result == -12) {
        throw new TStampPrecisionNotSupportedException(
            "Error occurred when set timestamp procision.");
      } else if (result == -4) {
        throw new ActivatedException("Error occurred when set timestamp procision.");
      }
      result = Pcap.MAPPING.pcap_activate(pointer);
      if (result == 2) {
        throw new PromiscNotSupported(Pointer.toString(Pcap.MAPPING.pcap_geterr(pointer)));
      } else if (result == 3) {
        LOGGER.warn(Pointer.toString(Pcap.MAPPING.pcap_statustostr(result)));
        // throw new TStampTypeNotSupportedException("Error occurred when activate a handle.");
      } else if (result == 1) {
        LOGGER.warn(Pointer.toString(Pcap.MAPPING.pcap_statustostr(result)));
        // throw new PcapWarningException("Error occurred when activate a handle.");
      } else if (result == -4) {
        throw new ActivatedException("Error occurred when activate a handle.");
      } else if (result == -5) {
        throw new NoSuchDeviceException(Pointer.toString(Pcap.MAPPING.pcap_geterr(pointer)));
      } else if (result == -8) {
        throw new PermissionDeniedException(Pointer.toString(Pcap.MAPPING.pcap_geterr(pointer)));
      } else if (result == -11) {
        throw new PromiscPermissionDeniedException("Error occurred when activate a handle.");
      } else if (result == -6) {
        throw new RfmonNotSupportedException("Error occurred when activate a handle.");
      } else if (result == -9) {
        throw new InterfaceNotUpException("Error occurred when activate a handle.");
      }
      return new Pcap(pointer, netmask());
    }
  }

  public Pcap openLive(int snaplen, boolean promiscuous, int timeout) throws PcapErrorException {
    synchronized (Pcap.LOCK) {
      Pointer<Byte> errbuf = Pcap.SCOPE.allocate(NativeTypes.INT8, Pcap.ERRBUF_SIZE);
      Pointer<pcap_mapping.pcap> pointer =
          Pcap.MAPPING.pcap_open_live(
              Pcap.SCOPE.allocateCString(name), snaplen, promiscuous ? 1 : 0, timeout, errbuf);
      if (pointer == null || pointer.isNull()) {
        throw new PcapErrorException(Pointer.toString(errbuf));
      }
      return new Pcap(pointer, netmask());
    }
  }

  public Pcap openLive() throws PcapErrorException {
    synchronized (Pcap.LOCK) {
      return openLive(65535, true, 2000);
    }
  }

  private int netmask() {
    if (addresses.netmask() instanceof Inet4Address) {
      byte[] address = addresses.netmask().getAddress();
      int ip = 0;
      for (int i = 0; i < 4; i++) {
        ip |= (address[i] & 0xff) << (3 - i) * 8;
      }
      return ip;
    }
    return 0xFFFFFF00;
  }
}

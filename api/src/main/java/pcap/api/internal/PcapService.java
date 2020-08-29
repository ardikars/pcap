package pcap.api.internal;

import java.foreign.NativeTypes;
import java.foreign.Scope;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Predicate;
import pcap.api.internal.foreign.mapping.PcapMapping;
import pcap.api.internal.foreign.pcap_header;
import pcap.api.internal.util.Platforms;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.common.util.Objects;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.exception.warn.PromiscuousModeNotSupported;

public class PcapService implements Service {

  private static final Logger LOGGER = LoggerFactory.getLogger(PcapService.class);

  private final String name;

  public PcapService() {
    this.name = "PcapService";
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public String version() {
    synchronized (PcapMapping.LOCK) {
      return Pointer.toString(PcapMapping.MAPPING.pcap_lib_version());
    }
  }

  @Override
  public Interface lookupInterfaces() throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<Pointer<pcap_header.pcap_if>> pointer =
            scope.allocate(LayoutType.ofStruct(pcap_header.pcap_if.class).pointer());
        Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapMapping.ERRBUF_SIZE);
        int result = PcapMapping.MAPPING.pcap_findalldevs(pointer, errbuf);
        if (result != PcapMapping.OK) {
          throw new ErrorException(Pointer.toString(errbuf));
        }
        pcap_header.pcap_if pcap_if = pointer.get().get();
        Interface devices = new PcapInterface(pcap_if);
        PcapMapping.MAPPING.pcap_freealldevs(pointer.get());
        return devices;
      }
    }
  }

  @Override
  public Interface lookupInterfaces(Predicate<Interface> predicate) throws ErrorException {
    List<Interface> collections = new LinkedList<>();
    Interface interfaces = lookupInterfaces();
    Iterator<Interface> interfaceIterator = interfaces.iterator();
    while (interfaceIterator.hasNext()) {
      Interface next = interfaceIterator.next();
      if (predicate.test(next)) {
        collections.add(next);
      }
    }
    if (collections.isEmpty()) {
      throw new ErrorException("Interface not found");
    }
    PcapInterface pcapInterface;
    Iterator<Interface> iterator = collections.iterator();
    pcapInterface = (PcapInterface) iterator.next();
    pcapInterface.next = null;
    while (iterator.hasNext()) {
      PcapInterface next = (PcapInterface) iterator.next();
      next.next = null;
      pcapInterface.next = next;
    }
    return pcapInterface;
  }

  @Override
  public Inet4Address lookupInet4Address(Interface source) throws ErrorException {
    if (source.addresses() != null) {
      Iterator<Address> addressIterator = source.addresses().iterator();
      while (addressIterator.hasNext()) {
        Address next = addressIterator.next();
        if (next.address() != null
            && !next.address().isLoopbackAddress()
            && next.address() instanceof Inet4Address) {
          return (Inet4Address) next.address();
        }
      }
    }
    throw new ErrorException("Not found.");
  }

  @Override
  public Inet6Address lookupInet6Address(Interface source) throws ErrorException {
    if (source.addresses() != null) {
      Iterator<Address> addressIterator = source.addresses().iterator();
      while (addressIterator.hasNext()) {
        Address next = addressIterator.next();
        if (next.address() != null
            && !next.address().isLoopbackAddress()
            && next.address() instanceof Inet6Address) {
          return (Inet6Address) next.address();
        }
      }
    }
    throw new ErrorException("IPv6 address not found for " + source.name());
  }

  @Override
  public Pcap offline(String source, OfflineOptions options) throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapMapping.ERRBUF_SIZE);
        Pointer<pcap_header.pcap> pointer;
        if (options.timestampPrecision() == null) {
          if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Opening file: {}", source);
          }
          pointer = PcapMapping.MAPPING.pcap_open_offline(scope.allocateCString(source), errbuf);
        } else {
          if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                "Opening file ({}) with timestamp precision ({})",
                source,
                options.timestampPrecision().value());
          }
          pointer =
              PcapMapping.MAPPING.pcap_open_offline_with_tstamp_precision(
                  scope.allocateCString(source), options.timestampPrecision().value(), errbuf);
        }
        nullCheck(pointer, errbuf);
        switch (Platforms.name()) {
          case LINUX:
            return new LinuxPcap(pointer);
          case DARWIN:
            return new DarwinPcap(pointer);
          case WINDOWS:
            return new WindowsPcap(pointer);
        }
        throw new UnsupportedOperationException();
      }
    }
  }

  @Override
  public Pcap live(Interface source, LiveOptions options)
      throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
          TimestampPrecisionNotSupportedException {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Opening live handler on {}.", source.name());
      }
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapMapping.ERRBUF_SIZE);
        Pointer<pcap_header.pcap> pointer =
            PcapMapping.MAPPING.pcap_create(scope.allocateCString(source.name()), errbuf);
        nullCheck(pointer, errbuf);
        checkSetSnaplen(PcapMapping.MAPPING.pcap_set_snaplen(pointer, options.snapshotLength()));
        checkSetPromisc(
            PcapMapping.MAPPING.pcap_set_promisc(pointer, options.isPromiscuous() ? 1 : 0));
        final int canSetRfmon =
            canSetRfmon(pointer, PcapMapping.MAPPING.pcap_can_set_rfmon(pointer));
        if (canSetRfmon == PcapMapping.OK) {
          checkSetRfmon(PcapMapping.MAPPING.pcap_set_rfmon(pointer, options.isRfmon() ? 1 : 0));
        }
        checkSetTimeout(PcapMapping.MAPPING.pcap_set_timeout(pointer, options.timeout()));
        if (Objects.nonNull(options.timestampType())) {
          checkSetTimestampType(
              PcapMapping.MAPPING.pcap_set_tstamp_type(pointer, options.timestampType().value()));
        }
        checkSetImmediateMode(
            PcapMapping.MAPPING.pcap_set_immediate_mode(pointer, options.isImmediate() ? 1 : 0));
        if (options.bufferSize() != 0) {
          checkSetBufferSize(
              PcapMapping.MAPPING.pcap_set_buffer_size(pointer, options.bufferSize()));
        }
        checkSetTimestampPrecision(
            PcapMapping.MAPPING.pcap_set_tstamp_precision(
                pointer, options.timestampPrecision().value()));
        checkActivate(pointer, PcapMapping.MAPPING.pcap_activate(pointer));
        switch (Platforms.name()) {
          case LINUX:
            return new LinuxPcap(pointer, netmask(source));
          case DARWIN:
            return new DarwinPcap(pointer, netmask(source));
          case WINDOWS:
            return new WindowsPcap(pointer, netmask(source));
        }
        throw new UnsupportedOperationException();
      }
    }
  }

  void nullCheck(Pointer<pcap_header.pcap> pointer, Pointer<Byte> errbuf) {
    if (pointer == null || pointer.isNull()) {
      throw new IllegalStateException(Pointer.toString(errbuf));
    }
  }

  void checkSetSnaplen(int result) throws ActivatedException {
    if (result != PcapMapping.OK) {
      throw new ActivatedException("Error occurred when set snapshot length.");
    }
  }

  void checkSetPromisc(int result) throws ActivatedException {
    if (result != PcapMapping.OK) {
      throw new ActivatedException("Error occurred when set promiscuous mode.");
    }
  }

  int canSetRfmon(Pointer<pcap_header.pcap> pointer, int result)
      throws ActivatedException, NoSuchDeviceException, ErrorException {
    if (result == -4) {
      throw new ActivatedException("Error occurred when set radio frequency monitor mode.");
    } else if (result == -5) {
      throw new NoSuchDeviceException("Error occurred when set radio frequency monitor mode.");
    } else {
      if (result == -1) {
        throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pointer)));
      } else {
        if (result < 0) {
          throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_statustostr(result)));
        } else {
          LOGGER.warn(
              "pcap_can_set_rfmon: {}",
              Pointer.toString(PcapMapping.MAPPING.pcap_statustostr(result)));
        }
      }
    }
    return result;
  }

  void checkSetRfmon(int result) throws ActivatedException {
    if (result != PcapMapping.OK) {
      throw new ActivatedException("Error occurred when set radio frequency monitor mode.");
    }
  }

  void checkSetTimeout(int result) throws ActivatedException {
    if (result != PcapMapping.OK) {
      throw new ActivatedException("Error occurred when set timeout.");
    }
  }

  void checkSetTimestampType(int result)
      throws ActivatedException, InterfaceNotSupportTimestampTypeException {
    if (result == -4) {
      throw new ActivatedException("Error occurred when set timestamp type.");
    } else if (result == -10) {
      throw new InterfaceNotSupportTimestampTypeException(
          "Error occurred when set timestamp type.");
    } else if (result == 3) {
      LOGGER.warn(
          "pcap_set_tstamp_type: {}",
          Pointer.toString(PcapMapping.MAPPING.pcap_statustostr(result)));
    }
  }

  void checkSetImmediateMode(int result) throws ActivatedException {
    if (result != PcapMapping.OK) {
      throw new ActivatedException("Error occurred when set immediate mode.");
    }
  }

  void checkSetBufferSize(int result) throws ActivatedException {
    if (result != PcapMapping.OK) {
      throw new ActivatedException("Error occurred when set buffer size.");
    }
  }

  void checkSetTimestampPrecision(int result)
      throws TimestampPrecisionNotSupportedException, ActivatedException {
    if (result == -12) {
      throw new TimestampPrecisionNotSupportedException(
          "Error occurred when set timestamp procision.");
    } else if (result == -4) {
      throw new ActivatedException("Error occurred when set timestamp procision.");
    }
  }

  void checkActivate(Pointer<pcap_header.pcap> pointer, int result)
      throws PromiscuousModePermissionDeniedException, RadioFrequencyModeNotSupportedException,
          InterfaceNotUpException, NoSuchDeviceException, ActivatedException,
          PermissionDeniedException {
    if (result == 2) {
      throw new PromiscuousModeNotSupported(
          Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pointer)));
    } else if (result == 3) {
      LOGGER.warn(
          "pcap_activate: {}", Pointer.toString(PcapMapping.MAPPING.pcap_statustostr(result)));
    } else if (result == 1) {
      LOGGER.warn(
          "pcap_activate: {}", Pointer.toString(PcapMapping.MAPPING.pcap_statustostr(result)));
    } else if (result == -4) {
      throw new ActivatedException("Error occurred when activate a handle.");
    } else if (result == -5) {
      throw new NoSuchDeviceException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pointer)));
    } else if (result == -8) {
      throw new PermissionDeniedException(
          Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pointer)));
    } else if (result == -11) {
      throw new PromiscuousModePermissionDeniedException("Error occurred when activate a handle.");
    } else if (result == -6) {
      throw new RadioFrequencyModeNotSupportedException("Error occurred when activate a handle.");
    } else if (result == -9) {
      throw new InterfaceNotUpException("Error occurred when activate a handle.");
    }
  }

  int netmask(Interface source) {
    int netmask = 0xFFFFFF00;
    if (source.addresses() != null && source.addresses().netmask() instanceof Inet4Address) {
      byte[] address = source.addresses().netmask().getAddress();
      for (int i = 0; i < 4; i++) {
        netmask |= (address[i] & 0xff) << (3 - i) * 8;
      }
    }
    return netmask;
  }
}

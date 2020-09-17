package pcap.api.jdk7;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.exception.warn.PromiscuousModeNotSupported;

public class DefaultService implements Service {

  private final ReentrantReadWriteLock.WriteLock lock =
      new ReentrantReadWriteLock(true).writeLock();

  private final NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();

  @Override
  public String name() {
    return "PcapService";
  }

  @Override
  public String version() {
    return NativeMappings.pcap_lib_version();
  }

  @Override
  public DefaultInterface lookupInterfaces() throws ErrorException {
    return interfaces();
  }

  @Override
  public DefaultInterface interfaces() throws ErrorException {
    DefaultInterface pcapIf;
    PointerByReference alldevsPP = new PointerByReference();
    lock.lock();
    try {
      checkFindAllDevs(NativeMappings.pcap_findalldevs(alldevsPP, errbuf(true)));
      Pointer alldevsp = alldevsPP.getValue();
      pcapIf = new DefaultInterface(alldevsp);
      NativeMappings.pcap_freealldevs(pcapIf.getPointer());
    } finally {
      lock.unlock();
    }
    return pcapIf;
  }

  @Override
  public Inet4Address lookupInet4Address(Interface source) throws ErrorException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Inet6Address lookupInet6Address(Interface source) throws ErrorException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Pcap offline(String source, OfflineOptions options) throws ErrorException {
    Pointer pointer;
    lock.lock();
    ;
    try {
      if (options.timestampPrecision() == null) {
        pointer = NativeMappings.pcap_open_offline(source, errbuf(true));
      } else {
        pointer =
            NativeMappings.PlatformDependent.INSTANCE.pcap_open_offline_with_tstamp_precision(
                source, options.timestampPrecision().value(), errbuf(true));
      }
      nullCheck(pointer);
    } finally {
      lock.unlock();
    }
    return new DefaultPcap(pointer, 0);
  }

  @Override
  public Pcap live(Interface source, LiveOptions options)
      throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
          TimestampPrecisionNotSupportedException {
    Pointer pointer;
    lock.lock();
    try {
      pointer = NativeMappings.pcap_create(source.name(), errbuf(true));
      nullCheck(pointer);
      checkSetSnaplen(NativeMappings.pcap_set_snaplen(pointer, options.snapshotLength()));
      checkSetPromisc(NativeMappings.pcap_set_promisc(pointer, options.isPromiscuous() ? 1 : 0));
      checkSetTimeout(NativeMappings.pcap_set_timeout(pointer, options.timeout()));
      if (Objects.nonNull(options.timestampType())) {
        checkSetTimestampType(
            NativeMappings.pcap_set_tstamp_type(pointer, options.timestampType().value()));
      }
      if (options.bufferSize() >= 0) {
        checkSetBufferSize(NativeMappings.pcap_set_buffer_size(pointer, options.bufferSize()));
      }
      boolean canSetRfmon = canSetRfmon(pointer, NativeMappings.pcap_can_set_rfmon(pointer));

      //  platform dependent
      setRfMonIfPossible(pointer, options.isRfmon(), canSetRfmon);
      checkSetImmediateMode(
          NativeMappings.PlatformDependent.INSTANCE.pcap_set_immediate_mode(
              pointer, options.isImmediate() ? 1 : 0));
      checkSetTimestampPrecision(
          NativeMappings.PlatformDependent.INSTANCE.pcap_set_tstamp_precision(
              pointer, options.timestampPrecision().value()));
      // end of platform dependent
      checkActivate(pointer, NativeMappings.pcap_activate(pointer));
    } finally {
      lock.unlock();
    }
    return new DefaultPcap(pointer, netmask(source));
  }

  void nullCheck(Pointer pointer) {
    if (pointer == null) {
      throw new IllegalStateException(errbuf.toString());
    }
  }

  void checkSetSnaplen(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException("Error occurred when set snapshot length.");
    }
  }

  void checkSetPromisc(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException("Error occurred when set promiscuous mode.");
    }
  }

  void setRfMonIfPossible(Pointer pointer, boolean rfmon, boolean canSetRfmon)
      throws ActivatedException {
    if (canSetRfmon) {
      checkSetRfmon(
          NativeMappings.PlatformDependent.INSTANCE.pcap_set_rfmon(pointer, rfmon ? 1 : 0));
    }
  }

  boolean canSetRfmon(Pointer pointer, int result)
      throws ActivatedException, NoSuchDeviceException, ErrorException {
    if (result == -4) {
      throw new ActivatedException("Error occurred when set radio frequency monitor mode.");
    } else if (result == -5) {
      throw new NoSuchDeviceException("Error occurred when set radio frequency monitor mode.");
    } else {
      if (result == -1) {
        throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
      } else {
        if (result < 0) {
          throw new ErrorException(NativeMappings.pcap_statustostr(result));
        } else {
          System.out.println("pcap_can_set_rfmon: " + NativeMappings.pcap_statustostr(result));
        }
      }
    }
    return result == NativeMappings.TRUE;
  }

  void checkSetRfmon(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException("Error occurred when set radio frequency monitor mode.");
    }
  }

  void checkSetTimeout(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
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
      System.out.println("pcap_set_tstamp_type: " + NativeMappings.pcap_statustostr(result));
    }
  }

  void checkSetImmediateMode(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException("Error occurred when set immediate mode.");
    }
  }

  void checkSetBufferSize(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
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

  void checkActivate(Pointer pointer, int result)
      throws PromiscuousModePermissionDeniedException, RadioFrequencyModeNotSupportedException,
          InterfaceNotUpException, NoSuchDeviceException, ActivatedException,
          PermissionDeniedException {
    if (result == 2) {
      throw new PromiscuousModeNotSupported(NativeMappings.pcap_geterr(pointer).getString(0));
    } else if (result == 3) {
      System.out.println("pcap_activate: " + NativeMappings.pcap_statustostr(result));
    } else if (result == 1) {
      System.out.println("pcap_activate: " + NativeMappings.pcap_statustostr(result));
    } else if (result == -4) {
      throw new ActivatedException("Error occurred when activate a handle.");
    } else if (result == -5) {
      throw new NoSuchDeviceException(NativeMappings.pcap_geterr(pointer).getString(0));
    } else if (result == -8) {
      throw new PermissionDeniedException(NativeMappings.pcap_geterr(pointer).getString(0));
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
    Address next = source.addresses();
    while (next != null) {
      if (next.netmask() instanceof Inet4Address) {
        byte[] address = next.netmask().getAddress();
        for (int i = 0; i < 4; i++) {
          netmask |= (address[i] & 0xff) << (3 - i) * 8;
        }
        return netmask;
      } else {
        next = next.next();
      }
    }
    return netmask;
  }

  void checkFindAllDevs(int result) throws ErrorException {
    if (result != 0) {
      throw new ErrorException(errbuf.toString());
    }
  }

  NativeMappings.ErrorBuffer errbuf(boolean clear) {
    if (clear) {
      errbuf.clear();
    }
    return errbuf;
  }
}

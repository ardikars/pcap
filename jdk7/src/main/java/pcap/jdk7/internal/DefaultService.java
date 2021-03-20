/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.net.Inet4Address;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.Selector;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.ActivatedException;
import pcap.spi.exception.error.InterfaceNotSupportTimestampTypeException;
import pcap.spi.exception.error.InterfaceNotUpException;
import pcap.spi.exception.error.NoSuchDeviceException;
import pcap.spi.exception.error.PermissionDeniedException;
import pcap.spi.exception.error.PromiscuousModePermissionDeniedException;
import pcap.spi.exception.error.RadioFrequencyModeNotSupportedException;
import pcap.spi.exception.error.TimestampPrecisionNotSupportedException;
import pcap.spi.exception.warn.PromiscuousModeNotSupported;

public class DefaultService implements Service {

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
  public Interface interfaces() throws ErrorException {
    PointerByReference alldevsPP = new PointerByReference();
    checkFindAllDevs(NativeMappings.pcap_findalldevs(alldevsPP, errbuf(true)));

    Pointer alldevsp = alldevsPP.getValue();
    NativeMappings.pcap_if pcapIf = new NativeMappings.pcap_if(alldevsp);
    NativeMappings.pcap_freealldevs(pcapIf.getPointer());
    return pcapIf;
  }

  @Override
  public Pcap offline(String source, OfflineOptions options) throws ErrorException {
    Utils.requireNonNull(source, "source: null (expected: source != null or !blank).");
    Pointer pointer;

    if (options.timestampPrecision() == null) {
      pointer = NativeMappings.pcap_open_offline(source, errbuf(true));
    } else {
      pointer = setOfflineWithTimestampPrecisionIfPossible(source, options);
    }
    nullCheck(pointer);

    return new DefaultPcap(pointer, 0);
  }

  @Override
  public Pcap live(Interface source, LiveOptions options)
      throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
          TimestampPrecisionNotSupportedException {
    Utils.requireNonNull(source, "source: null (expected: source != null).");
    Pointer pointer = NativeMappings.PLATFORM_DEPENDENT.pcap_create(source.name(), errbuf(true));
    if (pointer != null) {
      checkSetSnaplen(
          NativeMappings.PLATFORM_DEPENDENT.pcap_set_snaplen(pointer, options.snapshotLength()));
      checkSetPromisc(
          NativeMappings.PLATFORM_DEPENDENT.pcap_set_promisc(
              pointer, options.isPromiscuous() ? 1 : 0));
      checkSetTimeout(
          NativeMappings.PLATFORM_DEPENDENT.pcap_set_timeout(pointer, options.timeout()));
      if (options.bufferSize() >= 0) {
        checkSetBufferSize(
            NativeMappings.PLATFORM_DEPENDENT.pcap_set_buffer_size(pointer, options.bufferSize()));
      }
      boolean canSetRfmon =
          canSetRfmon(pointer, NativeMappings.PLATFORM_DEPENDENT.pcap_can_set_rfmon(pointer));

      //  platform dependent
      if (options.timestampType() != null) {
        setTimestampTypeIfPossible(pointer, options);
      }
      if (options.timestampPrecision() != null) {
        setTimestampPrecisionIfPossible(pointer, options);
      }

      setRfMonIfPossible(pointer, options.isRfmon(), canSetRfmon);
      if ((Platform.isWindows() || Platform.isWindowsCE()) && options.isImmediate()) {
        if (NativeMappings.PLATFORM_DEPENDENT.pcap_setmintocopy(pointer, 0) == -3) {
          checkActivate(pointer, NativeMappings.PLATFORM_DEPENDENT.pcap_activate(pointer));
          checkSetImmediateMode(NativeMappings.PLATFORM_DEPENDENT.pcap_setmintocopy(pointer, 0));
        }
      } else {
        setImmediateModeIfPossible(pointer, options);
        checkActivate(pointer, NativeMappings.PLATFORM_DEPENDENT.pcap_activate(pointer));
      }
    } else {
      pointer =
          NativeMappings.pcap_open_live(
              source.name(),
              options.snapshotLength(),
              options.isPromiscuous() ? 1 : 0,
              options.timeout(),
              errbuf);
      nullCheck(pointer);
    }
    return new DefaultPcap(pointer, netmask(source));
  }

  @Override
  public Selector selector() {
    if (Platform.isWindows()) {
      return new DefaultWaitForMultipleObjectsSelector();
    } else {
      return new DefaultPollSelector();
    }
  }

  Pointer setOfflineWithTimestampPrecisionIfPossible(String source, OfflineOptions options) {
    Pointer pointer =
        NativeMappings.PLATFORM_DEPENDENT.pcap_open_offline_with_tstamp_precision(
            source, options.timestampPrecision().value(), errbuf(true));
    if (pointer == null) { // fallback for backport support
      pointer = NativeMappings.pcap_open_offline(source, errbuf(true));
    }
    return pointer;
  }

  void nullCheck(Pointer pointer) throws ErrorException {
    if (pointer == null) {
      throw new ErrorException(errbuf.toString());
    }
  }

  void checkSetSnaplen(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException(
          statusToString(result, "Error occurred when set snapshot length"));
    }
  }

  void checkSetPromisc(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException(
          statusToString(result, "Error occurred when set promiscuous mode"));
    }
  }

  void setRfMonIfPossible(Pointer pointer, boolean rfmon, boolean canSetRfmon)
      throws ActivatedException {
    if (canSetRfmon) {
      checkSetRfmon(NativeMappings.PLATFORM_DEPENDENT.pcap_set_rfmon(pointer, rfmon ? 1 : 0));
    }
  }

  boolean canSetRfmon(Pointer pointer, int result)
      throws ActivatedException, NoSuchDeviceException, ErrorException {
    String message = "Error occurred when set radio frequency monitor mode";
    if (result == -4) {
      throw new ActivatedException(statusToString(result, message));
    } else if (result == -5) {
      throw new NoSuchDeviceException(statusToString(result, message));
    } else {
      if (result == -1) {
        throw new ErrorException(NativeMappings.pcap_geterr(pointer).getString(0));
      } else {
        if (result < 0) {
          throw new ErrorException(statusToString(result, message));
        } else {
          Utils.warn(statusToString(result, message));
        }
      }
    }
    return result == NativeMappings.TRUE;
  }

  void checkSetRfmon(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException(
          statusToString(result, "Error occurred when set radio frequency monitor mode"));
    }
  }

  void checkSetTimeout(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException(statusToString(result, "Error occurred when set timeout"));
    }
  }

  void setTimestampTypeIfPossible(Pointer pointer, LiveOptions options)
      throws ActivatedException, InterfaceNotSupportTimestampTypeException {
    checkSetTimestampType(
        NativeMappings.PLATFORM_DEPENDENT.pcap_set_tstamp_type(
            pointer, options.timestampType().value()));
  }

  void checkSetTimestampType(int result)
      throws ActivatedException, InterfaceNotSupportTimestampTypeException {
    String message = "Error occurred when set timestamp type";
    if (result == -4) {
      throw new ActivatedException(statusToString(result, message));
    } else if (result == -10) {
      throw new InterfaceNotSupportTimestampTypeException(statusToString(result, message));
    } else if (result == 3) {
      Utils.warn(statusToString(result, message));
    }
  }

  void setImmediateModeIfPossible(Pointer pointer, LiveOptions options) throws ActivatedException {
    checkSetImmediateMode(
        NativeMappings.PLATFORM_DEPENDENT.pcap_set_immediate_mode(
            pointer, options.isImmediate() ? 1 : 0));
  }

  void checkSetImmediateMode(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException(
          statusToString(result, "Error occurred when set immediate mode"));
    }
  }

  void checkSetBufferSize(int result) throws ActivatedException {
    if (result != NativeMappings.OK) {
      throw new ActivatedException(statusToString(result, "Error occurred when set buffer size"));
    }
  }

  void setTimestampPrecisionIfPossible(Pointer pointer, LiveOptions options)
      throws ActivatedException, TimestampPrecisionNotSupportedException {
    checkSetTimestampPrecision(
        NativeMappings.PLATFORM_DEPENDENT.pcap_set_tstamp_precision(
            pointer, options.timestampPrecision().value()));
  }

  void checkSetTimestampPrecision(int result)
      throws TimestampPrecisionNotSupportedException, ActivatedException {
    String message = "Error occurred when set timestamp procision";
    if (result == -12) {
      throw new TimestampPrecisionNotSupportedException(statusToString(result, message));
    } else if (result == -4) {
      throw new ActivatedException(statusToString(result, message));
    }
  }

  void checkActivate(Pointer pointer, int result)
      throws PromiscuousModePermissionDeniedException, RadioFrequencyModeNotSupportedException,
          InterfaceNotUpException, NoSuchDeviceException, ActivatedException,
          PermissionDeniedException {
    String message = "Error occurred when activate a handle";
    if (result == 2) {
      throw new PromiscuousModeNotSupported(NativeMappings.pcap_geterr(pointer).getString(0));
    } else if (result == 3) {
      Utils.warn(statusToString(result, message));
    } else if (result == 1) {
      Utils.warn(statusToString(result, message));
    } else if (result == -4) {
      throw new ActivatedException(statusToString(result, message));
    } else if (result == -5) {
      throw new NoSuchDeviceException(NativeMappings.pcap_geterr(pointer).getString(0));
    } else if (result == -8) {
      throw new PermissionDeniedException(NativeMappings.pcap_geterr(pointer).getString(0));
    } else if (result == -11) {
      throw new PromiscuousModePermissionDeniedException(statusToString(result, message));
    } else if (result == -6) {
      throw new RadioFrequencyModeNotSupportedException(statusToString(result, message));
    } else if (result == -9) {
      throw new InterfaceNotUpException(statusToString(result, message));
    }
  }

  String statusToString(int rc, String fallback) {
    try {
      return NativeMappings.PLATFORM_DEPENDENT.pcap_statustostr(rc);
    } catch (NullPointerException | UnsatisfiedLinkError e) {
      StringBuilder sb = new StringBuilder();
      sb.append(fallback);
      sb.append(" (");
      sb.append(rc);
      sb.append(").");
      return sb.toString();
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
      errbuf.getPointer().setMemory(0, errbuf.buf.length, (byte) '\0');
      errbuf.buf[0] = '\0'; // force set to empty string
    }
    return errbuf;
  }
}

/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.util.Iterator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.*;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;
import pcap.spi.exception.warn.PromiscuousModeNotSupported;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.option.DefaultOfflineOptions;

@RunWith(JUnitPlatform.class)
public class DefaultServiceTest extends BaseTest {

  private Service service;

  @BeforeEach
  void setUp() throws ErrorException {
    service = Service.Creator.create("PcapService");
  }

  @Test
  void version() {
    Assertions.assertNotNull(service.version());
  }

  @Test
  void interfaces() throws ErrorException {
    final DefaultService defaultService = (DefaultService) service;
    Iterator<Interface> sources = defaultService.interfaces().iterator();
    while (sources.hasNext()) {
      Interface source = sources.next();
      Assertions.assertTrue(source.next() != null || source.next() == null);
      Assertions.assertTrue(source.name() != null || source.name() == null);
      Assertions.assertTrue(source.description() != null || source.description() == null);
      Assertions.assertTrue(source.flags() >= 0);
      if (source.addresses() != null) {
        Iterator<Address> addresses = source.addresses().iterator();
        while (addresses.hasNext()) {
          Address address = addresses.next();
          Assertions.assertTrue(address.address() != null || address.address() == null);
          Assertions.assertTrue(address.netmask() != null || address.netmask() == null);
          Assertions.assertTrue(address.broadcast() != null || address.broadcast() == null);
          Assertions.assertTrue(address.destination() != null || address.destination() == null);
        }
      }
    }
  }

  @Test
  void live()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException, BreakException {
    Interface lo = loopbackInterface(service);
    try (Pcap live = service.live(lo, new DefaultLiveOptions().snapshotLength(-1))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().snapshotLength(0))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().snapshotLength(65535))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().promiscuous(true))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().promiscuous(false))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().rfmon(true))) {
      Assertions.assertNotNull(live);
    } catch (Throwable e) {
      Assertions.assertTrue(e instanceof RadioFrequencyModeNotSupportedException);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().rfmon(false))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().timeout(-1))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().timeout(0))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().timeout(1000))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().timestampType(null))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampType(Timestamp.Type.HOST))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampType(Timestamp.Type.HOST_LOWPREC))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampType(Timestamp.Type.HOST_HIPREC))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampType(Timestamp.Type.ADAPTER))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampType(Timestamp.Type.ADAPTER_UNSYNCED))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().immediate(true))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().immediate(false))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().bufferSize(-1))) {
      Assertions.assertNotNull(live);
    } catch (Throwable e) {
      Assertions.assertTrue(e instanceof ActivatedException);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().bufferSize(0))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().bufferSize(1024))) {
      Assertions.assertNotNull(live);
    }
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampPrecision(Timestamp.Precision.MICRO))) {
      Assertions.assertNotNull(live);
    } catch (TimestampPrecisionNotSupportedException e) {
    }
    try (Pcap live =
        service.live(lo, new DefaultLiveOptions().timestampPrecision(Timestamp.Precision.NANO))) {
      Assertions.assertNotNull(live);
    } catch (TimestampPrecisionNotSupportedException e) {
    }
    try (Pcap live = service.live(lo, new DefaultLiveOptions().proxy(Proxy.class))) {
      Assertions.assertNotNull(live);
    } catch (TimestampPrecisionNotSupportedException e) {
    }
  }

  @Test
  void offline() throws ErrorException {
    try (Pcap offline =
        service.offline(
            SAMPLE_NANOSECOND_PCAP,
            new DefaultOfflineOptions().timestampPrecision(Timestamp.Precision.MICRO))) {
      Assertions.assertNotNull(offline);
    } catch (ErrorException e) {
      Utils.warn(e.getMessage()); // pcap 1.2.1
    }
    try (Pcap offline =
        service.offline(
            SAMPLE_NANOSECOND_PCAP,
            new DefaultOfflineOptions().timestampPrecision(Timestamp.Precision.NANO))) {
      Assertions.assertNotNull(offline);
    } catch (ErrorException e) {
      Utils.warn(e.getMessage()); // pcap 1.2.1
    }
    try (Pcap offline =
        service.offline(
            SAMPLE_NANOSECOND_PCAP, new DefaultOfflineOptions().timestampPrecision(null))) {
      Assertions.assertNotNull(offline);
    } catch (ErrorException e) {
      Utils.warn(e.getMessage()); // pcap 1.2.1
    }
  }

  @Test
  void checkFindAllDevs() throws ErrorException {
    final DefaultService defaultService = (DefaultService) service;
    PointerByReference alldevsPP = new PointerByReference();
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    int rc = NativeMappings.pcap_findalldevs(alldevsPP, errbuf);
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkFindAllDevs(-1);
          }
        });
    defaultService.checkFindAllDevs(0);
    NativeMappings.pcap_freealldevs(alldevsPP.getValue());
  }

  @Test
  void checkSetSnaplen() throws ActivatedException {
    final DefaultService defaultService = (DefaultService) service;
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetSnaplen(-1);
          }
        });
    defaultService.checkSetSnaplen(0);
  }

  @Test
  void checkSetPromisc() throws ActivatedException {
    final DefaultService defaultService = (DefaultService) service;
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetPromisc(-1);
          }
        });
    defaultService.checkSetPromisc(0);
  }

  @Test
  void nullCheck() throws ErrorException {
    final DefaultService defaultService = (DefaultService) service;
    Interface lo = loopbackInterface(defaultService);
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    final Pointer pointer = NativeMappings.pcap_create(lo.name(), errbuf);
    defaultService.nullCheck(pointer);
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.nullCheck(null);
          }
        });
    NativeMappings.pcap_close(pointer);
  }

  @Test
  void canSetRfmon() throws ErrorException, ActivatedException, NoSuchDeviceException {
    final DefaultService defaultService = (DefaultService) service;
    Interface lo = loopbackInterface(defaultService);
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    final Pointer pointer = NativeMappings.pcap_create(lo.name(), errbuf);
    Assertions.assertNotNull(pointer);
    int rc = NativeMappings.PLATFORM_DEPENDENT.pcap_can_set_rfmon(pointer);
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.canSetRfmon(pointer, -4);
          }
        });
    Assertions.assertThrows(
        NoSuchDeviceException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.canSetRfmon(pointer, -5);
          }
        });
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.canSetRfmon(pointer, -1);
          }
        });
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.canSetRfmon(pointer, -100);
          }
        });
    Assertions.assertTrue(defaultService.canSetRfmon(pointer, 1));
    Assertions.assertFalse(defaultService.canSetRfmon(pointer, 0));
    NativeMappings.pcap_close(pointer);
  }

  @Test
  void checkSetRfmon() throws ActivatedException {
    final DefaultService defaultService = (DefaultService) service;
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetRfmon(-1);
          }
        });
    defaultService.checkSetRfmon(0);
  }

  @Test
  void checkSetTimeout() throws ActivatedException {
    final DefaultService defaultService = (DefaultService) service;
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetTimeout(-1);
          }
        });
    defaultService.checkSetTimeout(0);
  }

  @Test
  void checkSetTimestampType()
      throws ActivatedException, InterfaceNotSupportTimestampTypeException {
    final DefaultService defaultService = (DefaultService) service;
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetTimestampType(-4);
          }
        });
    Assertions.assertThrows(
        InterfaceNotSupportTimestampTypeException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetTimestampType(-10);
          }
        });
    defaultService.checkSetTimestampType(3);
    defaultService.checkSetTimestampType(0);
  }

  @Test
  void checkSetImmediateMode() throws ActivatedException {
    final DefaultService defaultService = (DefaultService) service;
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetImmediateMode(-1);
          }
        });
    defaultService.checkSetImmediateMode(0);
  }

  @Test
  void checkSetBufferSize() throws ActivatedException {
    final DefaultService defaultService = (DefaultService) service;
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetBufferSize(-1);
          }
        });
    defaultService.checkSetBufferSize(0);
  }

  @Test
  void checkSetTimestampPrecision()
      throws ActivatedException, TimestampPrecisionNotSupportedException {
    final DefaultService defaultService = (DefaultService) service;
    Assertions.assertThrows(
        TimestampPrecisionNotSupportedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetTimestampPrecision(-12);
          }
        });
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkSetTimestampPrecision(-4);
          }
        });
    defaultService.checkSetTimestampPrecision(0);
  }

  @Test
  void checkActivate()
      throws ErrorException, PromiscuousModePermissionDeniedException, PermissionDeniedException,
          RadioFrequencyModeNotSupportedException, ActivatedException, InterfaceNotUpException,
          NoSuchDeviceException {
    final DefaultService defaultService = (DefaultService) service;
    Interface lo = loopbackInterface(defaultService);
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    final Pointer pointer = NativeMappings.pcap_create(lo.name(), errbuf);
    Assertions.assertNotNull(pointer);
    int rc = NativeMappings.pcap_activate(pointer);
    Assertions.assertThrows(
        PromiscuousModeNotSupported.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkActivate(pointer, 2);
          }
        });
    defaultService.checkActivate(pointer, 3);
    defaultService.checkActivate(pointer, 1);
    Assertions.assertThrows(
        ActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkActivate(pointer, -4);
          }
        });
    Assertions.assertThrows(
        NoSuchDeviceException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkActivate(pointer, -5);
          }
        });
    Assertions.assertThrows(
        PermissionDeniedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkActivate(pointer, -8);
          }
        });
    Assertions.assertThrows(
        PromiscuousModePermissionDeniedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkActivate(pointer, -11);
          }
        });
    Assertions.assertThrows(
        RadioFrequencyModeNotSupportedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkActivate(pointer, -6);
          }
        });
    Assertions.assertThrows(
        InterfaceNotUpException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            defaultService.checkActivate(pointer, -9);
          }
        });
    defaultService.checkActivate(pointer, 0);
    NativeMappings.pcap_close(pointer);
  }

  @Test
  void netmask() throws ErrorException {
    final DefaultService defaultService = (DefaultService) service;
    Iterator<Interface> iterator = service.interfaces().iterator();
    while (iterator.hasNext()) {
      Interface source = iterator.next();
      Address next = source.addresses();
      boolean notNull = false;
      while (next != null) {
        if (next.netmask() != null) {
          notNull = true;
        }
        next = next.next();
      }
      if (!notNull) {
        defaultService.netmask(source);
      } else {
        defaultService.netmask(source);
      }
    }
  }

  @Test
  void errbuf() {
    final DefaultService defaultService = (DefaultService) service;
    NativeMappings.ErrorBuffer errbuf = defaultService.errbuf(true);
    errbuf.getPointer().setString(0, "Hello!");
    Assertions.assertEquals("Hello!", defaultService.errbuf(false).getPointer().getString(0));
    Assertions.assertEquals(
        "Hello!".length(), defaultService.errbuf(false).getPointer().getString(0).length());
    Assertions.assertEquals(0, defaultService.errbuf(true).toString().length());
  }

  @Test
  void setRfmon() throws ErrorException, ActivatedException, NoSuchDeviceException {
    final DefaultService defaultService = (DefaultService) service;

    DefaultLiveOptions options = new DefaultLiveOptions();
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();

    Interface lo = loopbackInterface(defaultService);
    final Pointer pointer = NativeMappings.pcap_create(lo.name(), errbuf);

    if (NativeMappings.pcap_set_snaplen(pointer, options.snapshotLength()) == NativeMappings.OK) {
      if (NativeMappings.pcap_set_promisc(pointer, options.isPromiscuous() ? 1 : 0)
          == NativeMappings.OK) {
        if (NativeMappings.pcap_set_timeout(pointer, options.timeout()) == NativeMappings.OK) {
          defaultService.setRfMonIfPossible(pointer, true, true);
          defaultService.setRfMonIfPossible(pointer, false, true);
          defaultService.setRfMonIfPossible(pointer, true, false);
          defaultService.setRfMonIfPossible(pointer, false, false);
          NativeMappings.pcap_close(pointer);
        }
      }
    }
  }

  interface Proxy extends Pcap {}
}

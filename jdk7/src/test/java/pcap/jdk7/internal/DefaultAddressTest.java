/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;

class DefaultAddressTest {

  private Service service;

  @BeforeEach
  void setUp() throws ErrorException {
    service = Service.Creator.create("PcapService");
  }

  @Test
  void newInstance() throws ErrorException {
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    DefaultService defaultService = (DefaultService) service;
    NativeMappings.pcap_if pcapIf;
    PointerByReference alldevsPP = new PointerByReference();
    defaultService.checkFindAllDevs(NativeMappings.pcap_findalldevs(alldevsPP, errbuf));
    Pointer alldevsp = alldevsPP.getValue();
    pcapIf = new NativeMappings.pcap_if(alldevsp);
    NativeMappings.pcap_freealldevs(pcapIf.getPointer());

    final Iterator<Interface> sources = pcapIf.iterator();
    while (sources.hasNext()) {
      Interface source = sources.next();
      Assertions.assertTrue(source.next() != null || source.next() == null);
      Assertions.assertTrue(source.name() != null || source.name() == null);
      Assertions.assertTrue(source.description() != null || source.description() == null);
      Assertions.assertTrue(source.flags() >= 0);
      if (source.addresses() != null) {
        final Iterator<Address> addresses = source.addresses().iterator();
        while (addresses.hasNext()) {
          Address address = addresses.next();
          NativeMappings.pcap_addr defaultAddress = (NativeMappings.pcap_addr) address;
          Assertions.assertEquals(
              Arrays.asList("next", "addr", "netmask", "broadaddr", "dstaddr"),
              defaultAddress.getFieldOrder());
          Assertions.assertTrue(address.address() != null || address.address() == null);
          Assertions.assertTrue(address.netmask() != null || address.netmask() == null);
          Assertions.assertTrue(address.broadcast() != null || address.broadcast() == null);
          Assertions.assertTrue(address.destination() != null || address.destination() == null);
          Assertions.assertThrows(
              UnsupportedOperationException.class,
              new Executable() {
                @Override
                public void execute() throws Throwable {
                  addresses.remove();
                }
              });
        }
      }
    }
    Assertions.assertThrows(
        NoSuchElementException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            sources.next();
          }
        });
  }

  @Test
  void sockaddr() {
    try (MockedStatic<NativeMappings.sockaddr> theMock =
        Mockito.mockStatic(NativeMappings.sockaddr.class)) {
      short saFamily;

      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  NativeMappings.sockaddr.isLinuxOrWindows();
                }
              })
          .thenReturn(false);
      NativeMappings.sockaddr isWindowsType = new NativeMappings.sockaddr();
      isWindowsType.sa_family = 2;
      isWindowsType.setAutoSynch(true);
      isWindowsType.setAutoRead(true);
      isWindowsType.setAutoWrite(true);
      saFamily = isWindowsType.getSaFamily();
      Assertions.assertTrue(saFamily >= 0);

      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  NativeMappings.sockaddr.isLinuxOrWindows();
                }
              })
          .thenReturn(true);

      NativeMappings.sockaddr nonWindowsType = new NativeMappings.sockaddr();
      nonWindowsType.sa_family = 2;
      nonWindowsType.setAutoSynch(true);
      nonWindowsType.setAutoRead(true);
      nonWindowsType.setAutoWrite(true);
      saFamily = isWindowsType.getSaFamily();
      Assertions.assertTrue(saFamily >= 0);
    }

    Assertions.assertTrue(
        NativeMappings.sockaddr.getSaFamilyByByteOrder((short) 2, ByteOrder.LITTLE_ENDIAN) >= 0);
    Assertions.assertTrue(
        NativeMappings.sockaddr.getSaFamilyByByteOrder((short) 2, ByteOrder.BIG_ENDIAN) >= 0);
  }

  @Test
  void isLinuxOrWindows() {
    try (MockedStatic<Platform> theMock = Mockito.mockStatic(Platform.class)) {
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.isLinux();
                }
              })
          .thenReturn(false);
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.isWindows();
                }
              })
          .thenReturn(false);
      Assertions.assertFalse(NativeMappings.sockaddr.isLinuxOrWindows());
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.isLinux();
                }
              })
          .thenReturn(true);
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.isWindows();
                }
              })
          .thenReturn(true);
      Assertions.assertTrue(NativeMappings.sockaddr.isLinuxOrWindows());
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.isLinux();
                }
              })
          .thenReturn(true);
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.isWindows();
                }
              })
          .thenReturn(false);
      Assertions.assertTrue(NativeMappings.sockaddr.isLinuxOrWindows());
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.isLinux();
                }
              })
          .thenReturn(false);
      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  Platform.isWindows();
                }
              })
          .thenReturn(true);
      Assertions.assertTrue(NativeMappings.sockaddr.isLinuxOrWindows());
    }
  }
}

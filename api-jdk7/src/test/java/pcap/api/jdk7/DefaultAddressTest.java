package pcap.api.jdk7;

import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Iterator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;

@RunWith(JUnitPlatform.class)
public class DefaultAddressTest {

  private Service service;

  @BeforeEach
  public void setUp() throws ErrorException {
    service = Service.Creator.create("PcapService");
  }

  @Test
  public void newInstance() throws ErrorException {
    NativeMappings.ErrorBuffer errbuf = new NativeMappings.ErrorBuffer();
    DefaultService defaultService = (DefaultService) service;
    DefaultInterface pcapIf;
    PointerByReference alldevsPP = new PointerByReference();
    defaultService.checkFindAllDevs(NativeMappings.pcap_findalldevs(alldevsPP, errbuf));
    Pointer alldevsp = alldevsPP.getValue();
    pcapIf = new DefaultInterface(alldevsp);
    NativeMappings.pcap_freealldevs(pcapIf.getPointer());

    Iterator<Interface> sources = pcapIf.iterator();
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
          DefaultAddress defaultAddress = (DefaultAddress) address;
          Assertions.assertEquals(
              Arrays.asList("next", "addr", "netmask", "broadaddr", "dstaddr"),
              defaultAddress.getFieldOrder());
          Assertions.assertTrue(address.address() != null || address.address() == null);
          Assertions.assertTrue(address.netmask() != null || address.netmask() == null);
          Assertions.assertTrue(address.broadcast() != null || address.broadcast() == null);
          Assertions.assertTrue(address.destination() != null || address.destination() == null);
        }
      }
    }
  }

  @Test
  public void sockaddr() {
    try (MockedStatic<DefaultAddress.sockaddr> theMock =
        Mockito.mockStatic(DefaultAddress.sockaddr.class)) {
      short saFamily;

      theMock
          .when(
              new MockedStatic.Verification() {
                @Override
                public void apply() throws Throwable {
                  DefaultAddress.sockaddr.isLinuxOrWindows();
                }
              })
          .thenReturn(false);
      DefaultAddress.sockaddr isWindowsType = new DefaultAddress.sockaddr();
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
                  DefaultAddress.sockaddr.isLinuxOrWindows();
                }
              })
          .thenReturn(true);

      DefaultAddress.sockaddr nonWindowsType = new DefaultAddress.sockaddr();
      nonWindowsType.sa_family = 2;
      nonWindowsType.setAutoSynch(true);
      nonWindowsType.setAutoRead(true);
      nonWindowsType.setAutoWrite(true);
      saFamily = isWindowsType.getSaFamily();
      Assertions.assertTrue(saFamily >= 0);
    }

    Assertions.assertTrue(
        DefaultAddress.sockaddr.getSaFamilyByByteOrder((short) 2, ByteOrder.LITTLE_ENDIAN) >= 0);
    Assertions.assertTrue(
        DefaultAddress.sockaddr.getSaFamilyByByteOrder((short) 2, ByteOrder.BIG_ENDIAN) >= 0);
  }

  @Test
  public void isLinuxOrWindows() {
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
      Assertions.assertFalse(DefaultAddress.sockaddr.isLinuxOrWindows());
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
      Assertions.assertTrue(DefaultAddress.sockaddr.isLinuxOrWindows());
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
      Assertions.assertTrue(DefaultAddress.sockaddr.isLinuxOrWindows());
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
      Assertions.assertTrue(DefaultAddress.sockaddr.isLinuxOrWindows());
    }
  }
}

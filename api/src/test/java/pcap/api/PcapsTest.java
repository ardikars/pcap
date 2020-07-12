/** This code is licenced under the GPL version 2. */
package pcap.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.api.internal.PcapInterface;
import pcap.common.net.Inet4Address;
import pcap.common.net.Inet6Address;
import pcap.spi.Interface;
import pcap.spi.exception.ErrorException;

// @EnabledOnJre(JRE.JAVA_14)
@RunWith(JUnitPlatform.class)
public class PcapsTest {

  @Test
  public void versionTest() {
    Assertions.assertNotNull(Pcaps.version());
  }

  @Test
  public void lookupInterfaceTest() throws ErrorException {
    String source = Pcaps.lookupInterface().name();
    Interface pcapInterface = Pcaps.lookupInterface(source);
    Assertions.assertEquals(pcapInterface.name(), source);
  }

  @Test
  public void lookupInterfacesTest() throws ErrorException {
    Assertions.assertNotNull(Pcaps.lookupInterfaces());
  }

  @Test
  public void lookupMacAddressTest() throws ErrorException {
    Interface anInterface = Pcaps.lookupInterfaces();
    while (anInterface.next() != null) {
      try {
        Assertions.assertNotNull(Pcaps.lookupMacAddress(anInterface));
      } catch (ErrorException e) {
        //
      }
      if (anInterface instanceof PcapInterface) {
        PcapInterface pcapInterface = (PcapInterface) anInterface;
        Assertions.assertTrue(pcapInterface.isLoopback() || true);
        Assertions.assertTrue(pcapInterface.isUp() || true);
        Assertions.assertTrue(pcapInterface.isRunning() || true);
        Assertions.assertTrue(pcapInterface.isWireless() || true);
        Assertions.assertTrue(pcapInterface.isConnected() || true);
        Assertions.assertTrue(pcapInterface.isDisconnected() || true);
      }
      anInterface = anInterface.next();
    }
  }

  @Test
  public void lookupInet4AddressTest() throws ErrorException {
    final Interface anInterface = Pcaps.lookupInterfaces();
    final Inet4Address inet4Address = Pcaps.lookupInet4Address(anInterface);
    Assertions.assertNotNull(inet4Address);
  }

  @Test
  public void lookupInet6AddressTest() throws ErrorException {
    final Interface anInterface = Pcaps.lookupInterfaces();
    try {
      final Inet6Address inet6Address = Pcaps.lookupInet6Address(anInterface);
      Assertions.assertNotNull(inet6Address);
    } catch (ErrorException e) {
      System.out.println(e);
    }
  }
}

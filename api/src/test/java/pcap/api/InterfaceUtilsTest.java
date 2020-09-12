package pcap.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.common.net.MacAddress;
import pcap.spi.Interface;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;

@RunWith(JUnitPlatform.class)
public class InterfaceUtilsTest {

  @Test
  public void lookupHardwareAddressTest() throws ErrorException {
    Service pcaps = Service.Creator.create("PcapService");
    Assertions.assertNotNull(pcaps);
    try {
      // non loopback
      Interface source =
          pcaps.lookupInterfaces(anInterface -> !((anInterface.flags() & 0x00000001) != 0));
      MacAddress macAddress = InterfaceUtils.lookupHardwareAddress(source, MacAddress.class);
      Assertions.assertNotNull(macAddress);
    } catch (ErrorException e) {
      Assertions.assertThrows(
          ErrorException.class,
          () -> {
            throw new ErrorException(e.getMessage());
          });
    }
    // loopback
    Interface source =
        pcaps.lookupInterfaces(anInterface -> (anInterface.flags() & 0x00000001) != 0);
    Assertions.assertThrows(
        ErrorException.class, () -> InterfaceUtils.lookupHardwareAddress(source, MacAddress.class));
  }
}

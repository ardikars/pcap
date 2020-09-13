package pcap.api;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Predicate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.api.internal.PcapInterface;
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
          lookupInterfaces(pcaps, anInterface -> !((anInterface.flags() & 0x00000001) != 0));
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
        lookupInterfaces(pcaps, anInterface -> (anInterface.flags() & 0x00000001) != 0);
    Assertions.assertThrows(
        ErrorException.class, () -> InterfaceUtils.lookupHardwareAddress(source, MacAddress.class));
  }

  private Interface lookupInterfaces(Service pcaps, Predicate<Interface> predicate)
      throws ErrorException {
    List<Interface> collections = new LinkedList<>();
    Interface interfaces = pcaps.lookupInterfaces();
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
}

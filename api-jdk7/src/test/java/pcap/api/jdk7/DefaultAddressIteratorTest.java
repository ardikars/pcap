package pcap.api.jdk7;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;

@RunWith(JUnitPlatform.class)
public class DefaultAddressIteratorTest {

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
        Assertions.assertThrows(
            NoSuchElementException.class,
            new Executable() {
              @Override
              public void execute() throws Throwable {
                addresses.next();
              }
            });
      }
    }
  }

  @Test
  public void useMemoryFromReferece() {
    PointerByReference pointerByReference = new PointerByReference();
    pointerByReference.setPointer(new Memory(1));
    DefaultPacketBuffer structureReference = new DefaultPacketBuffer();
    structureReference.useMemoryFromReferece();
    structureReference.useMemoryFromReferece();
    pointerByReference.setPointer(null);
    structureReference.useMemoryFromReferece();
  }
}

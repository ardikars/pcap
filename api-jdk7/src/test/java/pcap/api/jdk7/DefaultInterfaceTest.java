package pcap.api.jdk7;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.Interface;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;

@RunWith(JUnitPlatform.class)
public class DefaultInterfaceTest {

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

    Assertions.assertEquals(
        Arrays.asList("next", "name", "description", "addresses", "flags"), pcapIf.getFieldOrder());

    Iterator<Interface> iterator = pcapIf.iterator();
    while (iterator.hasNext()) {
      Interface next = iterator.next();
      Assertions.assertTrue(Objects.nonNull(next.next()) || Objects.isNull(next.next()));
      Assertions.assertNotNull(next.name());
      Assertions.assertTrue(Objects.nonNull(next.name()) || Objects.isNull(next.description()));
      Assertions.assertTrue(
          Objects.nonNull(next.description()) || Objects.isNull(next.description()));
      Assertions.assertTrue(Objects.nonNull(next.addresses()) || Objects.isNull(next.addresses()));
      Assertions.assertTrue(next.flags() >= 0);
    }
  }
}

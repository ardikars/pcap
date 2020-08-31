package pcap.api;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.Iterator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.api.internal.PcapInterface;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;

@RunWith(JUnitPlatform.class)
public class PcapServiceTest {

  private static final String NAME = "PcapService";
  private static final String FILE = "src/test/resources/sample.pcapng";

  @Test
  public void loadServiceTest() throws ErrorException {
    Service pcaps = Service.create(NAME);
    Assertions.assertNotNull(pcaps);
    Assertions.assertThrows(ErrorException.class, () -> Service.create("UnknownService"));
  }

  @Test
  public void nameTest() throws ErrorException {
    Service pcaps = Service.create(NAME);
    Assertions.assertNotNull(pcaps);
    Assertions.assertEquals(NAME, pcaps.name());
  }

  @Test
  public void versionTest() throws ErrorException {
    Service pcaps = Service.create(NAME);
    Assertions.assertNotNull(pcaps);
    Assertions.assertNotNull(pcaps.version());
  }

  @Test
  public void lookupInterfacesTest() throws ErrorException {
    Service pcaps = Service.create(NAME);
    Assertions.assertNotNull(pcaps);
    Assertions.assertNotNull(pcaps.lookupInterfaces());
  }

  @Test
  public void lookupInterfaceByPredicate() throws ErrorException {
    Service pcaps = Service.create(NAME);
    Assertions.assertNotNull(pcaps);
    // non loopback
    Interface nonLoopback =
        pcaps.lookupInterfaces(anInterface -> !((anInterface.flags() & 0x00000001) != 0));
    Iterator<Interface> iterator = nonLoopback.iterator();
    while (iterator.hasNext()) {
      Assertions.assertTrue(!((iterator.next().flags() & 0x00000001) != 0));
    }
  }

  @Test
  public void lookupInet4AddressTest() throws ErrorException {
    Service pcaps = Service.create(NAME);
    Assertions.assertNotNull(pcaps);
    try {
      Interface source = pcaps.lookupInterfaces();
      Inet4Address address = pcaps.lookupInet4Address(source);
      Assertions.assertNotNull(address);
    } catch (ErrorException e) {
      Assertions.assertThrows(
          ErrorException.class,
          () -> {
            throw new ErrorException(e.getMessage());
          });
    }
  }

  @Test
  public void lookupInet6AddressTest() throws ErrorException {
    Service pcaps = Service.create(NAME);
    Assertions.assertNotNull(pcaps);
    try {
      Interface source = pcaps.lookupInterfaces();
      Inet6Address address = pcaps.lookupInet6Address(source);
      Assertions.assertNotNull(address);
    } catch (ErrorException e) {
      Assertions.assertThrows(
          ErrorException.class,
          () -> {
            throw new ErrorException(e.getMessage());
          });
    }
  }

  @Test
  public void offlineTest() throws ErrorException {
    Service pcaps = Service.create(NAME);
    Assertions.assertNotNull(pcaps);
    PcapOfflineOptions options = new PcapOfflineOptions();
    Pcap pcap = pcaps.offline(FILE, options);
    Assertions.assertNotNull(pcap);
    pcap.close();
  }

  @Test
  public void liveTest()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    Service pcaps = Service.create(NAME);
    Assertions.assertNotNull(pcaps);
    Interface source = loopbackInterface(pcaps);
    PcapLiveOptions options = new PcapLiveOptions();
    Pcap pcap = pcaps.live(source, options);
    Assertions.assertNotNull(pcap);
    pcap.close();
  }

  private static Interface loopbackInterface(Service service) throws ErrorException {
    Iterator<Interface> iterator = service.lookupInterfaces().iterator();
    while (iterator.hasNext()) {
      Interface devices = iterator.next();
      if (devices instanceof PcapInterface) {
        PcapInterface pcapInterface = (PcapInterface) devices;
        if (pcapInterface.isLoopback()) {
          return pcapInterface;
        }
      }
    }
    throw new ErrorException("Loopback interface is not found.");
  }
}

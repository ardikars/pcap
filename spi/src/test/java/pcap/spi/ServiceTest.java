package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.exception.ErrorException;

@RunWith(JUnitPlatform.class)
public class ServiceTest {

  @Test
  public void createTest() throws ErrorException {
    Assertions.assertThrows(ErrorException.class, () -> Service.create("TestService"));
    Service service = Service.create("NoService");
    Assertions.assertTrue(service instanceof Service.NoService);
  }

  @Test
  public void noServiceTest() throws ErrorException {
    Service service = Service.create("NoService");
    Assertions.assertEquals("NoService", service.name());
    Assertions.assertEquals("0.0.0", service.version());
    Assertions.assertThrows(ErrorException.class, () -> service.lookupInterfaces());
    Assertions.assertThrows(ErrorException.class, () -> service.lookupInterfaces(null));
    Assertions.assertThrows(ErrorException.class, () -> service.lookupInet4Address(null));
    Assertions.assertThrows(ErrorException.class, () -> service.lookupInet6Address(null));
    Assertions.assertThrows(ErrorException.class, () -> service.offline(null, null));
    Assertions.assertThrows(ErrorException.class, () -> service.live(null, null));
  }
}

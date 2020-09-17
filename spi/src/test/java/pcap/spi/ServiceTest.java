package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.exception.ErrorException;

@RunWith(JUnitPlatform.class)
public class ServiceTest {

  @Test
  public void createTest() throws ErrorException {
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Service.Creator.create("TestService");
          }
        });
    Service service = Service.Creator.create("NoService");
    Assertions.assertTrue(service instanceof Service.NoService);
  }

  @Test
  public void noServiceTest() throws ErrorException {
    final Service service = Service.Creator.create("NoService");
    Assertions.assertEquals("NoService", service.name());
    Assertions.assertEquals("0.0.0", service.version());
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            service.lookupInterfaces();
          }
        });
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            service.interfaces();
          }
        });
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            service.lookupInet4Address(null);
          }
        });
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            service.lookupInet6Address(null);
          }
        });
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            service.offline(null, null);
          }
        });
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            service.live(null, null);
          }
        });
  }
}

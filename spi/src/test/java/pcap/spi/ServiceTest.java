/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;

@RunWith(JUnitPlatform.class)
public class ServiceTest {

  @Test
  void createTest() throws ErrorException {
    Assertions.assertThrows(
        ErrorException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            Service.Creator.create("TestService");
          }
        });
    Assertions.assertTrue(Service.Creator.create("NoService") instanceof NoService);
  }

  @Test
  void noServiceTest() throws ErrorException {
    final Service service = Service.Creator.create("NoService");
    Assertions.assertEquals("NoService", service.name());
    Assertions.assertEquals("0.0.0", service.version());
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

  /**
   * No service provider.
   *
   * @since 1.0.0
   */
  public static final class NoService implements Service {

    /** {@inheritDoc} */
    @Override
    public String name() {
      return "NoService";
    }

    /** {@inheritDoc} */
    @Override
    public String version() {
      return "0.0.0";
    }

    /** {@inheritDoc} */
    @Override
    public Interface interfaces() throws ErrorException {
      throw new ErrorException("No API implementation.");
    }

    /** {@inheritDoc} */
    @Override
    public Pcap offline(String source, OfflineOptions options) throws ErrorException {
      throw new ErrorException("No API implementation.");
    }

    /** {@inheritDoc} */
    @Override
    public Pcap live(Interface source, LiveOptions options)
        throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
            RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
            NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
            TimestampPrecisionNotSupportedException {
      throw new ErrorException("No API implementation.");
    }

    @Override
    public Selector selector() {
      throw new RuntimeException("No API implementation.");
    }
  }
}

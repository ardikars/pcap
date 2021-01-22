/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Platform;
import java.util.Iterator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import pcap.spi.Pcap;
import pcap.spi.Selectable;
import pcap.spi.Selector;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;
import pcap.spi.option.DefaultLiveOptions;

@RunWith(JUnitPlatform.class)
class DefaultPollSelectorTest extends AbstractSelectorTest {

  boolean isUnix() {
    return !Platform.isWindows() && !Platform.isWindowsCE();
  }

  @Test
  void register()
      throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          BreakException, NoSuchDeviceException, PromiscuousModePermissionDeniedException,
          ErrorException, TimestampPrecisionNotSupportedException {
    registerTest();
  }

  @Test
  void pollfdTest() {
    DefaultPollSelector.pollfd pollfd1 = new DefaultPollSelector.pollfd();
    DefaultPollSelector.pollfd pollfd2 = new DefaultPollSelector.pollfd();
    Assertions.assertEquals(pollfd1, pollfd2);
    pollfd1.fd = 1;
    Assertions.assertNotEquals(pollfd1, pollfd2);
    Assertions.assertTrue(pollfd1.hashCode() > 0);
  }

  @Test
  void notRegistered() throws ErrorException, TimeoutException {
    if (!isUnix()) {
      Assertions.assertFalse(isUnix());
      return;
    }
    final Service service = Service.Creator.create("PcapService");
    final Selector selector = service.selector();
    final DefaultPollSelector pollSelector = (DefaultPollSelector) selector;
    Iterable<Selectable> selected1 = pollSelector.toIterable(-1, 0);
    Iterator<Selectable> iterator1 = selected1.iterator();
    Assertions.assertFalse(iterator1.hasNext());
    Iterable<Selectable> selected2 = pollSelector.toIterable(10, 0);
    Iterator<Selectable> iterator2 = selected2.iterator();
    Assertions.assertFalse(iterator2.hasNext());

    Assertions.assertFalse(pollSelector.toIterable(0, 0).iterator().hasNext());

    Assertions.assertThrows(
        TimeoutException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            try (Pcap live = service.live(service.interfaces(), new DefaultLiveOptions())) {
              pollSelector.register(live);
              pollSelector.toIterable(0, 0);
            }
          }
        });
  }

  @Test
  void doubleRegister()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    doubleRegisterTest();
  }
}

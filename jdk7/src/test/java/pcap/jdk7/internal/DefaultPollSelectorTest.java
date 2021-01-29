/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Platform;
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

import java.util.ArrayList;
import java.util.Iterator;

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
    Assertions.assertTrue(pollfd1.equals(pollfd1));
    Assertions.assertTrue(pollfd1.equals(pollfd2));
    Assertions.assertFalse(pollfd1.equals(new ArrayList<String>()));
    pollfd1.fd = 1;
    Assertions.assertFalse(pollfd1.equals(pollfd2));
    Assertions.assertTrue(pollfd1.hashCode() > 0);
  }

  @Test
  void doWhile() throws ErrorException {
    if (!isUnix()) {
      Assertions.assertFalse(isUnix());
      return;
    }
    final Service service = Service.Creator.create("PcapService");
    final Selector selector = service.selector();
    DefaultPollSelector pollSelector = (DefaultPollSelector) selector;
    Assertions.assertFalse(pollSelector.doWhile(0, DefaultPollSelector.EINTR));
    Assertions.assertFalse(pollSelector.doWhile(-1, DefaultPollSelector.EINTR + 1));
    Assertions.assertTrue(pollSelector.doWhile(-1, DefaultPollSelector.EINTR));
  }

  @Test
  void toIterable()
      throws ErrorException, TimeoutException, PermissionDeniedException,
          PromiscuousModePermissionDeniedException, TimestampPrecisionNotSupportedException,
          RadioFrequencyModeNotSupportedException, NoSuchDeviceException, ActivatedException,
          InterfaceNotUpException, InterfaceNotSupportTimestampTypeException {
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
    Pcap pcap = service.live(service.interfaces(), new DefaultLiveOptions());
    pollSelector.register(pcap);
    SelectableList<Selectable> selectables = new SelectableList<>();
    pollSelector.addToList(pollSelector.pfds[0].fd, 0, selectables);
    Assertions.assertNull(selectables.head);
    pollSelector.addToList(pollSelector.pfds[0].fd, DefaultPollSelector.POLLIN, selectables);
    Assertions.assertTrue(selectables.head != null);

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
    pcap.close();
  }

  @Test
  void doubleRegister()
      throws ErrorException, PermissionDeniedException, PromiscuousModePermissionDeniedException,
          TimestampPrecisionNotSupportedException, RadioFrequencyModeNotSupportedException,
          NoSuchDeviceException, ActivatedException, InterfaceNotUpException,
          InterfaceNotSupportTimestampTypeException {
    doubleRegisterTest();
  }

  @Test
  void badArgs()
      throws TimeoutException, InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
          TimestampPrecisionNotSupportedException {
    badArgsTest();
  }
}

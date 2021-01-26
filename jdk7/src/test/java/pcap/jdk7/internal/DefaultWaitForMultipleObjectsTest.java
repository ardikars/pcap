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
import pcap.spi.Selectable;
import pcap.spi.Selector;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.*;

import java.util.Iterator;

@RunWith(JUnitPlatform.class)
class DefaultWaitForMultipleObjectsTest extends AbstractSelectorTest {

  boolean isWindows() {
    return Platform.isWindows() || Platform.isWindowsCE();
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
  void notRegistered() throws ErrorException, TimeoutException {
    if (!isWindows()) {
      Assertions.assertFalse(isWindows());
      return;
    }
    Service service = Service.Creator.create("PcapService");
    Selector selector = service.selector();
    final DefaultWaitForMultipleObjectsSelector objectsSelector =
        (DefaultWaitForMultipleObjectsSelector) selector;
    Iterable<Selectable> selected1 = objectsSelector.toIterable(-1, 0);
    Iterator<Selectable> iterator1 = selected1.iterator();
    Assertions.assertFalse(iterator1.hasNext());
    Iterable<Selectable> selected2 = objectsSelector.toIterable(10, 0);
    Iterator<Selectable> iterator2 = selected2.iterator();
    Assertions.assertFalse(iterator2.hasNext());

    Assertions.assertThrows(
        TimeoutException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            objectsSelector.toIterable(0x00000102, 0);
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

  @Test
  void badArgs()
      throws TimeoutException, InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
          TimestampPrecisionNotSupportedException {
    badArgsTest();
  }
}

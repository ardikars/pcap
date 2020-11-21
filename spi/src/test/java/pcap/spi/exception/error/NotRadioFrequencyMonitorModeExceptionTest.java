/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * Operation supported only in monitor mode ({@code -7}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class NotRadioFrequencyMonitorModeExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        NotRadioFrequencyMonitorModeException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new NotRadioFrequencyMonitorModeException("throwing exception.");
          }
        });
  }
}

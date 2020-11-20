/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * This device doesn't support rfmon (monitor) mode ({@code -6}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class RadioFrequencyModeNotSupportedExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        RadioFrequencyModeNotSupportedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new RadioFrequencyModeNotSupportedException("throwing exception.");
          }
        });
  }
}

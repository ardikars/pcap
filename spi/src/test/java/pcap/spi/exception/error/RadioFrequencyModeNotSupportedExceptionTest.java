/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * This device doesn't support rfmon (monitor) mode ({@code -6}).
 *
 * @since 1.0.0
 */
class RadioFrequencyModeNotSupportedExceptionTest {

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

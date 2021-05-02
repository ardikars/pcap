/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * The requested time stamp precision is not supported ({@code -12}).
 *
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
class TimestampPrecisionNotSupportedExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        TimestampPrecisionNotSupportedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new TimestampPrecisionNotSupportedException("throwing exception.");
          }
        });
  }
}

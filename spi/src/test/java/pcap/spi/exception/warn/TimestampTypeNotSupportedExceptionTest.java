/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.warn;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** */
class TimestampTypeNotSupportedExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        TimestampTypeNotSupportedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new TimestampTypeNotSupportedException("throwing exception.");
          }
        });
  }
}

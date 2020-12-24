/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.warn;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** */
@RunWith(JUnitPlatform.class)
public class TimestampTypeNotSupportedExceptionTest {

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

/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Loop terminated by pcap_breakloop ({@code -2}).
 *
 * @since 1.0.0
 */
class BreakExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        BreakException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new BreakException("throwing exception.");
          }
        });
  }
}

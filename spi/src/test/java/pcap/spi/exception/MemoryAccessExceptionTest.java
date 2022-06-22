/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** */
class MemoryAccessExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        MemoryAccessException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new MemoryAccessException("throwing exception.");
          }
        });
  }
}

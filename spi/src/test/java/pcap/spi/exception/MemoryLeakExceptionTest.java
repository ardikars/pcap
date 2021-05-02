/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** */
@RunWith(JUnitPlatform.class)
class MemoryLeakExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        MemoryLeakException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new MemoryLeakException("throwing exception.");
          }
        });
  }
}

/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * No permission to open the device ({@code -8}).
 *
 * @since 1.0.0
 */
class PermissionDeniedExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        PermissionDeniedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new PermissionDeniedException("throwing exception.");
          }
        });
  }
}

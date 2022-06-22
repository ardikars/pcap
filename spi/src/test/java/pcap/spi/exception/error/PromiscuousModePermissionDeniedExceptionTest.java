/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * You don't have permission to capture in promiscuous mode ({@code -11}).
 *
 * @since 1.0.0
 */
class PromiscuousModePermissionDeniedExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        PromiscuousModePermissionDeniedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new PromiscuousModePermissionDeniedException("throwing exception.");
          }
        });
  }
}

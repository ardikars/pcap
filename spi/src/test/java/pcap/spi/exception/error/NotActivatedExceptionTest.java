/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * The capture needs to be activated ({@code -3}).
 *
 * @since 1.0.0
 */
class NotActivatedExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        NotActivatedException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new NotActivatedException("throwing exception.");
          }
        });
  }
}

/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * No permission to open the device ({@code -8}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class PermissionDeniedExceptionTest {

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

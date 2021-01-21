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
 * No such device exists ({@code -5}).
 *
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class NoSuchDeviceExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        NoSuchDeviceException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new NoSuchDeviceException("throwing exception.");
          }
        });
  }
}

/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.spi.exception;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class WarningExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        WarningException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new WarningException("throwing exception.");
          }
        });
  }
}

/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.warn;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class PromiscuousModeNotSupportedTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        PromiscuousModeNotSupported.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new PromiscuousModeNotSupported("throwing exception.");
          }
        });
  }
}

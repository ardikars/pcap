/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * This device doesn't support setting the time stamp type ({@code 10}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class InterfaceNotSupportTimestampTypeExceptionTest {

  @Test
  void throwExceptionTest() {
    Assertions.assertThrows(
        InterfaceNotSupportTimestampTypeException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            throw new InterfaceNotSupportTimestampTypeException("throwing exception.");
          }
        });
  }
}

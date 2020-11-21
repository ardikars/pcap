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
 * The capture needs to be activated ({@code -3}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class NotActivatedExceptionTest {

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

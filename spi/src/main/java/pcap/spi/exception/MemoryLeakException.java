/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

import pcap.spi.annotation.Incubating;

/**
 * Memory leak detected.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Incubating
public class MemoryLeakException extends RuntimeException {

  public MemoryLeakException(String message) {
    super(message);
  }
}

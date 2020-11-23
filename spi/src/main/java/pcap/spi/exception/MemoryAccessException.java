/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

import pcap.spi.annotation.Incubating;

/**
 * Illegal memory access.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Incubating
public class MemoryAccessException extends RuntimeException {

  public MemoryAccessException(String message) {
    super(message);
  }
}

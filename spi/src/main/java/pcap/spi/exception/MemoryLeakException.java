/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

import pcap.spi.annotation.Incubating;

/**
 * Memory leak detected.
 *
 * @since 1.0.0
 */
@Incubating
public class MemoryLeakException extends RuntimeException {

  public MemoryLeakException(String message) {
    super(message);
  }
}

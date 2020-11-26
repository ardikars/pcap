/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

/**
 * Memory leak detected.
 *
 * @since 1.0.0
 */
public class MemoryLeakException extends RuntimeException {

  public MemoryLeakException(String message) {
    super(message);
  }
}

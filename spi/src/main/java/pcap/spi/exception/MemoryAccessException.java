/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

/**
 * Illegal memory access.
 *
 * @since 1.0.0
 */
public class MemoryAccessException extends RuntimeException {

  /**
   * Create new MemoryAccessException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public MemoryAccessException(String message) {
    super(message);
  }
}

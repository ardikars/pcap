/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * Loop terminated by pcap_breakloop ({@code -2}).
 *
 * @since 1.0.0
 */
public class BreakException extends Exception {

  /**
   * Create new BreakException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public BreakException(String message) {
    super(message);
  }
}

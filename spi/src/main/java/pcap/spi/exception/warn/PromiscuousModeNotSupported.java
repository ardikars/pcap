/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.warn;

/**
 * This device doesn't support promiscuous mode ({@code 2}).
 *
 * @since 1.0.0
 */
public class PromiscuousModeNotSupported extends RuntimeException {

  /**
   * Create new PromiscuousModeNotSupported instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public PromiscuousModeNotSupported(String message) {
    super(message);
  }
}

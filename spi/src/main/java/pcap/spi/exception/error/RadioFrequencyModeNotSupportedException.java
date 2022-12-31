/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * This device doesn't support rfmon (monitor) mode ({@code -6}).
 *
 * @since 1.0.0
 */
public class RadioFrequencyModeNotSupportedException extends Exception {

  /**
   * Create new RadioFrequencyModeNotSupportedException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public RadioFrequencyModeNotSupportedException(String message) {
    super(message);
  }
}

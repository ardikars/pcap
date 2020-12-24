/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * Operation supported only in monitor mode ({@code -7}).
 *
 * @since 1.0.0
 */
public class NotRadioFrequencyMonitorModeException extends Exception {

  /**
   * Create new NotRadioFrequencyMonitorModeException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public NotRadioFrequencyMonitorModeException(String message) {
    super(message);
  }
}

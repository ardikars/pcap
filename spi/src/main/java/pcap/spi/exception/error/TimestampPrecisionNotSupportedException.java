/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * The requested time stamp precision is not supported ({@code -12}).
 *
 * @since 1.0.0
 */
public class TimestampPrecisionNotSupportedException extends Exception {

  /**
   * Create new TimestampPrecisionNotSupportedException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public TimestampPrecisionNotSupportedException(String message) {
    super(message);
  }
}

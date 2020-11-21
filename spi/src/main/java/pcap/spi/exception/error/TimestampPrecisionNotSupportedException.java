/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * The requested time stamp precision is not supported ({@code -12}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class TimestampPrecisionNotSupportedException extends Exception {

  public TimestampPrecisionNotSupportedException(String message) {
    super(message);
  }
}

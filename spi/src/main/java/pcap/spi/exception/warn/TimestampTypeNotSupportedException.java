/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.warn;

/**
 * The requested time stamp type is not supported ({@code 3}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class TimestampTypeNotSupportedException extends RuntimeException {

  public TimestampTypeNotSupportedException(String message) {
    super(message);
  }
}

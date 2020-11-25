/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.warn;

/**
 * The requested time stamp type is not supported ({@code 3}).
 *
 * @since 1.0.0
 */
public class TimestampTypeNotSupportedException extends RuntimeException {

  public TimestampTypeNotSupportedException(String message) {
    super(message);
  }
}

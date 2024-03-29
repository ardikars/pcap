/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * This device doesn't support setting the time stamp type ({@code 10}).
 *
 * @since 1.0.0
 */
public class InterfaceNotSupportTimestampTypeException extends Exception {

  /**
   * Create new InterfaceNotSupportTimestampTypeException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public InterfaceNotSupportTimestampTypeException(String message) {
    super(message);
  }
}

/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * No such device exists ({@code -5}).
 *
 * @since 1.0.0
 */
public class NoSuchDeviceException extends Exception {

  /**
   * Create new NoSuchDeviceException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public NoSuchDeviceException(String message) {
    super(message);
  }
}

/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * The capture needs to be activated ({@code -3}).
 *
 * @since 1.0.0
 */
public class NotActivatedException extends Exception {

  /**
   * Create new NotActivatedException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public NotActivatedException(String message) {
    super(message);
  }
}

/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * The operation can't be performed on already activated captures ({@code -4}).
 *
 * @since 1.0.0
 */
public class ActivatedException extends Exception {

  /**
   * Create new ActivatedException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public ActivatedException(String message) {
    super(message);
  }
}

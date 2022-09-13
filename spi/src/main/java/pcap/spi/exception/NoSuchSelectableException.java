/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

/**
 * No such {@link pcap.spi.Selectable} registered on {@link pcap.spi.Selector}.
 *
 * @since 1.2.0
 */
public class NoSuchSelectableException extends RuntimeException {

  /**
   * Create new NoSuchSelectableException instance.
   *
   * @param message message.
   * @since 1.2.0
   */
  public NoSuchSelectableException(String message) {
    super(message);
  }
}

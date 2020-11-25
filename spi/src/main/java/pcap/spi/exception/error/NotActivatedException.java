/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * The capture needs to be activated ({@code -3}).
 *
 * @since 1.0.0
 */
public class NotActivatedException extends Exception {

  public NotActivatedException(String message) {
    super(message);
  }
}

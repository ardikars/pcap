/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception;

/**
 * Timeout occurred while reading packet's.
 *
 * @since 1.0.0
 */
public class TimeoutException extends Exception {

  public TimeoutException(String message) {
    super(message);
  }
}

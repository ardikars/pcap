/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * Interface isn't up ({@code -9}).
 *
 * @since 1.0.0
 */
public class InterfaceNotUpException extends Exception {

  public InterfaceNotUpException(String message) {
    super(message);
  }
}

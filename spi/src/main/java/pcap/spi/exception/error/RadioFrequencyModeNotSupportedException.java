/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.spi.exception.error;

/**
 * This device doesn't support rfmon (monitor) mode ({@code -6}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class RadioFrequencyModeNotSupportedException extends Exception {

  public RadioFrequencyModeNotSupportedException(String message) {
    super(message);
  }
}

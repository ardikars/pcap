/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * Operation supported only in monitor mode ({@code -7}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class NotRadioFrequencyMonitorModeException extends Exception {

  public NotRadioFrequencyMonitorModeException(String message) {
    super(message);
  }
}

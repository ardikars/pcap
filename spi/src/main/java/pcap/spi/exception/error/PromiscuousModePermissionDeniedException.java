/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.spi.exception.error;

/**
 * You don't have permission to capture in promiscuous mode ({@code -11}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class PromiscuousModePermissionDeniedException extends Exception {

  public PromiscuousModePermissionDeniedException(String message) {
    super(message);
  }
}

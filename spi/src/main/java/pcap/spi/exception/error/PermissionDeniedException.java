/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.spi.exception.error;

/**
 * No permission to open the device ({@code -8}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class PermissionDeniedException extends Exception {

  public PermissionDeniedException(String message) {
    super(message);
  }
}

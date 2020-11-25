/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * No permission to open the device ({@code -8}).
 *
 * @since 1.0.0
 */
public class PermissionDeniedException extends Exception {

  public PermissionDeniedException(String message) {
    super(message);
  }
}

/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * You don't have permission to capture in promiscuous mode ({@code -11}).
 *
 * @since 1.0.0
 */
public class PromiscuousModePermissionDeniedException extends Exception {

  /**
   * Create new PromiscuousModePermissionDeniedException instance.
   *
   * @param message message.
   * @since 1.0.0
   */
  public PromiscuousModePermissionDeniedException(String message) {
    super(message);
  }
}

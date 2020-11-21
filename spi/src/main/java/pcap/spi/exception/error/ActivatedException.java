/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.exception.error;

/**
 * The operation can't be performed on already activated captures ({@code -4}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class ActivatedException extends Exception {

  public ActivatedException(String message) {
    super(message);
  }
}

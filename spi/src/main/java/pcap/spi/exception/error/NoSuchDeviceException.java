/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.spi.exception.error;

/**
 * No such device exists ({@code -5}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class NoSuchDeviceException extends Exception {

  public NoSuchDeviceException(String message) {
    super(message);
  }
}

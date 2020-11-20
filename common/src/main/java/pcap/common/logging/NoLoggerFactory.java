/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.common.logging;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
final class NoLoggerFactory extends LoggerFactory {

  private static final LoggerFactory INSTANCE = new NoLoggerFactory();

  public static LoggerFactory getInstance() {
    return INSTANCE;
  }

  @Override
  Logger newInstance(String name) {
    return new NoLogger(name);
  }
}

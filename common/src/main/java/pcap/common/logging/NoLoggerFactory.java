/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

/**
 * No logger factory.
 *
 * @since 1.0.0
 */
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

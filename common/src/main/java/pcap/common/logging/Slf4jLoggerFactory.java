/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

/**
 * Slf4j logger factory.
 *
 * @since 1.0.0
 */
final class Slf4jLoggerFactory extends LoggerFactory {

  private static final LoggerFactory INSTANCE = new Slf4jLoggerFactory();

  private static final boolean HAS_SLF4J;

  static {
    HAS_SLF4J = hasClass("org.slf4j.LoggerFactory");
  }

  private Slf4jLoggerFactory() {
    //
  }

  public static boolean hasSlf4j() {
    return HAS_SLF4J;
  }

  public static LoggerFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Logger newInstance(String name) {
    return new Slf4jLogger(org.slf4j.LoggerFactory.getLogger(name));
  }
}

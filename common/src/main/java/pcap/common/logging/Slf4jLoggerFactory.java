/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
final class Slf4jLoggerFactory extends LoggerFactory {

  private static final LoggerFactory INSTANCE = new Slf4jLoggerFactory();

  private static final boolean HAS_SLF4J;

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

  static {
    HAS_SLF4J = hasClass("org.slf4j.LoggerFactory");
  }
}

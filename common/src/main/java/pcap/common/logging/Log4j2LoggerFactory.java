/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

import org.apache.logging.log4j.LogManager;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
final class Log4j2LoggerFactory extends LoggerFactory {

  private static final LoggerFactory INSTANCE = new Log4j2LoggerFactory();

  private static final boolean HAS_LOG4J2;

  private Log4j2LoggerFactory() {
    //
  }

  public static boolean hasLog4j2() {
    return HAS_LOG4J2;
  }

  public static LoggerFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public Logger newInstance(String name) {
    return new Log4j2Logger(LogManager.getLogger(name));
  }

  static {
    HAS_LOG4J2 = hasClass("org.apache.logging.log4j.LogManager");
  }
}

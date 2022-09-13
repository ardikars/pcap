/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

/**
 * Logger factory.
 *
 * @since 1.0.0
 */
public abstract class LoggerFactory {

  static LoggerFactory DEFAULT_LOGGER_FACTORY;

  private static LoggerFactory getDefaultLoggerFactory() {
    if (DEFAULT_LOGGER_FACTORY == null) {
      DEFAULT_LOGGER_FACTORY = newDefaultFactory();
    }
    return DEFAULT_LOGGER_FACTORY;
  }

  /**
   * Get logger by name.
   *
   * @param name name.
   * @return returns new {@link Logger} instance.
   * @since 1.0.0
   */
  public static Logger getLogger(String name) {
    return getDefaultLoggerFactory().newInstance(name);
  }

  /**
   * Get logger by class.
   *
   * @param clazz class.
   * @return returns new {@link Logger} instance.
   * @since 1.0.0
   */
  public static Logger getLogger(Class<?> clazz) {
    return getLogger(clazz.getName());
  }

  /**
   * Get logger by object.
   *
   * @param object object.
   * @return returns new {@link Logger} instance.
   * @since 1.0.0
   */
  public static Logger getLogger(Object object) {
    return getLogger(object.getClass());
  }

  private static LoggerFactory newDefaultFactory() {
    LoggerFactory loggerFactory;
    if (Slf4jLoggerFactory.hasSlf4j()) {
      loggerFactory = Slf4jLoggerFactory.getInstance();
    } else if (Log4j2LoggerFactory.hasLog4j2()) {
      loggerFactory = Log4j2LoggerFactory.getInstance();
    } else {
      loggerFactory = NoLoggerFactory.getInstance();
    }
    return loggerFactory;
  }

  static boolean hasClass(String name) {
    try {
      Class.forName(name);
      return true;
    } catch (ClassNotFoundException e) {
      return false;
    }
  }

  abstract Logger newInstance(String name);
}

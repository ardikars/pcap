/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

import org.slf4j.Logger;

/**
 * Slf4j implementation.
 *
 * @since 1.0.0
 */
final class Slf4jLogger extends AbstractLogger {

  private final Logger logger;

  Slf4jLogger(Logger logger) {
    super(logger.getName());
    this.logger = logger;
  }

  @Override
  public boolean isDebugEnabled() {
    return logger.isDebugEnabled();
  }

  @Override
  public boolean isInfoEnabled() {
    return logger.isInfoEnabled();
  }

  @Override
  public boolean isWarnEnabled() {
    return logger.isWarnEnabled();
  }

  @Override
  public boolean isErrorEnabled() {
    return logger.isErrorEnabled();
  }

  @Override
  public void debug(String format, Object arg1) {
    logger.debug(format, arg1);
  }

  @Override
  public void debug(String format, Object arg1, Object arg2) {
    logger.debug(format, arg1, arg2);
  }

  @Override
  public void debug(String format, Object... args) {
    logger.debug(format, args);
  }

  @Override
  public void debug(String format, Throwable throwable) {
    logger.debug(format, throwable);
  }

  @Override
  public void info(String format, Object obj1) {
    logger.info(format, obj1);
  }

  @Override
  public void info(String format, Object obj1, Object obj2) {
    logger.info(format, obj1, obj2);
  }

  @Override
  public void info(String format, Object... args) {
    logger.info(format, args);
  }

  @Override
  public void info(String format, Throwable throwable) {
    logger.info(format, throwable);
  }

  @Override
  public void warn(String format, Object arg1) {
    logger.warn(format, arg1);
  }

  @Override
  public void warn(String format, Object arg1, Object obj2) {
    logger.warn(format, arg1, obj2);
  }

  @Override
  public void warn(String format, Object... args) {
    logger.warn(format, args);
  }

  @Override
  public void warn(String format, Throwable throwable) {
    logger.warn(format, throwable);
  }

  @Override
  public void error(String format, Object obj1) {
    logger.error(format, obj1);
  }

  @Override
  public void error(String format, Object obj1, Object obj2) {
    logger.error(format, obj1, obj2);
  }

  @Override
  public void error(String format, Object... args) {
    logger.error(format, args);
  }

  @Override
  public void error(String format, Throwable throwable) {
    logger.error(format, throwable);
  }
}

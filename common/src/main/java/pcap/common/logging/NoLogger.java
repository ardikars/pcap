/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

/**
 * No logger implementation.
 *
 * @since 1.0.0
 */
final class NoLogger implements Logger {

  private final String name;

  NoLogger(String name) {
    this.name = name;
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public boolean isEnabled(LogLevel level) {
    if (level == LogLevel.UNKNOWN) {
      throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
    return false;
  }

  @Override
  public boolean isDebugEnabled() {
    return false;
  }

  @Override
  public boolean isInfoEnabled() {
    return false;
  }

  @Override
  public boolean isWarnEnabled() {
    return false;
  }

  @Override
  public boolean isErrorEnabled() {
    return false;
  }

  @Override
  public void log(LogLevel level, Object message) {
    if (level == LogLevel.UNKNOWN) {
      throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Object arg1) {
    if (level == LogLevel.UNKNOWN) {
      throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Object arg1, Object arg2) {
    if (level == LogLevel.UNKNOWN) {
      throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Object... args) {
    if (level == LogLevel.UNKNOWN) {
      throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, Throwable throwable) {
    if (level == LogLevel.UNKNOWN) {
      throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String message, Throwable throwable) {
    if (level == LogLevel.UNKNOWN) {
      throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void debug(Object message) {}

  @Override
  public void debug(Throwable throwable) {}

  @Override
  public void debug(String format, Object arg1) {}

  @Override
  public void debug(String format, Object arg1, Object arg2) {}

  @Override
  public void debug(String format, Object... args) {}

  @Override
  public void debug(String message, Throwable throwable) {}

  @Override
  public void info(Object message) {}

  @Override
  public void info(Throwable throwable) {}

  @Override
  public void info(String format, Object obj1) {}

  @Override
  public void info(String format, Object obj1, Object obj2) {}

  @Override
  public void info(String format, Object... args) {}

  @Override
  public void info(String message, Throwable throwable) {}

  @Override
  public void warn(Object message) {}

  @Override
  public void warn(Throwable throwable) {}

  @Override
  public void warn(String format, Object arg1) {}

  @Override
  public void warn(String format, Object arg1, Object obj2) {}

  @Override
  public void warn(String format, Object... args) {}

  @Override
  public void warn(String message, Throwable throwable) {}

  @Override
  public void error(Object message) {}

  @Override
  public void error(Throwable throwable) {}

  @Override
  public void error(String format, Object obj1) {}

  @Override
  public void error(String format, Object obj1, Object obj2) {}

  @Override
  public void error(String format, Object... args) {}

  @Override
  public void error(String message, Throwable throwable) {}
}

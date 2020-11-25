/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

/**
 * Logger api specification.
 *
 * @since 1.0.0
 */
public interface Logger {

  /**
   * Logger holder name.
   *
   * @return returns logger name.
   * @since 1.0.0
   */
  String name();

  /**
   * Check the given level is enabled or not.
   *
   * @param level logging level.
   * @return returns {@code true} if given level is enabled, {@code otherwise}.
   */
  boolean isEnabled(LogLevel level);

  boolean isDebugEnabled();

  boolean isInfoEnabled();

  boolean isWarnEnabled();

  boolean isErrorEnabled();

  void log(LogLevel level, Object message);

  void log(LogLevel level, String format, Object arg1);

  void log(LogLevel level, String format, Object arg1, Object arg2);

  void log(LogLevel level, String format, Object... args);

  void log(LogLevel level, Throwable throwable);

  void log(LogLevel level, String message, Throwable throwable);

  void debug(Object message);

  void debug(Throwable throwable);

  void debug(String format, Object arg1);

  void debug(String format, Object arg1, Object arg2);

  void debug(String format, Object... args);

  void debug(String message, Throwable throwable);

  void info(Object message);

  void info(Throwable throwable);

  void info(String format, Object obj1);

  void info(String format, Object obj1, Object obj2);

  void info(String format, Object... args);

  void info(String message, Throwable throwable);

  void warn(Object message);

  void warn(Throwable throwable);

  void warn(String format, Object arg1);

  void warn(String format, Object arg1, Object obj2);

  void warn(String format, Object... args);

  void warn(String message, Throwable throwable);

  void error(Object message);

  void error(Throwable throwable);

  void error(String format, Object obj1);

  void error(String format, Object obj1, Object obj2);

  void error(String format, Object... args);

  void error(String message, Throwable throwable);
}

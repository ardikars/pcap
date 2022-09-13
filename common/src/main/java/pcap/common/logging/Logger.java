/*
 * Copyright (c) 2020-2022 Pcap Project
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
   * @since 1.0.0
   */
  boolean isEnabled(LogLevel level);

  /**
   * Check whether debug level is enabled.
   *
   * @return returns {@code} if enabled, {@code false} otherwise.
   * @since 1.0.0
   */
  boolean isDebugEnabled();

  /**
   * Check whether info level is enabled.
   *
   * @return returns {@code} if enabled, {@code false} otherwise.
   * @since 1.0.0
   */
  boolean isInfoEnabled();

  /**
   * Check whether warn level is enabled.
   *
   * @return returns {@code} if enabled, {@code false} otherwise.
   * @since 1.0.0
   */
  boolean isWarnEnabled();

  /**
   * Check whether error level is enabled.
   *
   * @return returns {@code} if enabled, {@code false} otherwise.
   * @since 1.0.0
   */
  boolean isErrorEnabled();

  /**
   * Log for specific log level.
   *
   * @param level level.
   * @param message message.
   * @since 1.0.0
   */
  void log(LogLevel level, Object message);

  /**
   * Log for specific log level.
   *
   * @param level level.
   * @param format format.
   * @param arg1 arg1.
   * @since 1.0.0
   */
  void log(LogLevel level, String format, Object arg1);

  /**
   * Log for specific log level.
   *
   * @param level level.
   * @param format format.
   * @param arg1 arg1.
   * @param arg2 arg2.
   * @since 1.0.0
   */
  void log(LogLevel level, String format, Object arg1, Object arg2);

  /**
   * Log for specific log level.
   *
   * @param level level.
   * @param format format.
   * @param args var args.
   * @since 1.0.0
   */
  void log(LogLevel level, String format, Object... args);

  /**
   * Log for specific log level.
   *
   * @param level level.
   * @param throwable throwable.
   * @since 1.0.0
   */
  void log(LogLevel level, Throwable throwable);

  /**
   * Log for specific log level.
   *
   * @param level level.
   * @param message message.
   * @param throwable throwable.
   * @since 1.0.0
   */
  void log(LogLevel level, String message, Throwable throwable);

  /**
   * Log debug.
   *
   * @param message message.
   * @since 1.0.0
   */
  void debug(Object message);

  /**
   * Log debug.
   *
   * @param throwable throwable.
   * @since 1.0.0
   */
  void debug(Throwable throwable);

  /**
   * Log debug.
   *
   * @param format format.
   * @param arg1 arg1.
   * @since 1.0.0
   */
  void debug(String format, Object arg1);

  /**
   * Log debug.
   *
   * @param format format.
   * @param arg1 arg1.
   * @param arg2 arg2.
   * @since 1.0.0
   */
  void debug(String format, Object arg1, Object arg2);

  /**
   * Log debug.
   *
   * @param format format.
   * @param args var args.
   * @since 1.0.0
   */
  void debug(String format, Object... args);

  /**
   * Log debug.
   *
   * @param message message.
   * @param throwable throwable.
   * @since 1.0.0
   */
  void debug(String message, Throwable throwable);

  /**
   * Log info.
   *
   * @param message message.
   * @since 1.0.0
   */
  void info(Object message);

  /**
   * Log info.
   *
   * @param throwable throwable.
   * @since 1.0.0
   */
  void info(Throwable throwable);

  /**
   * Log info.
   *
   * @param format format.
   * @param obj1 arg1.
   * @since 1.0.0
   */
  void info(String format, Object obj1);

  /**
   * Log info.
   *
   * @param format format.
   * @param obj1 arg1.
   * @param obj2 arg2.
   * @since 1.0.0
   */
  void info(String format, Object obj1, Object obj2);

  /**
   * Log info.
   *
   * @param format format.
   * @param args var args.
   * @since 1.0.0
   */
  void info(String format, Object... args);

  /**
   * Log info.
   *
   * @param message message.
   * @param throwable throwable.
   * @since 1.0.0
   */
  void info(String message, Throwable throwable);

  /**
   * Log warn.
   *
   * @param message message.
   * @since 1.0.0
   */
  void warn(Object message);

  /**
   * Log warn.
   *
   * @param throwable throwable.
   * @since 1.0.0
   */
  void warn(Throwable throwable);

  /**
   * Log warn,
   *
   * @param format format.
   * @param arg1 arg1.
   * @since 1.0.0
   */
  void warn(String format, Object arg1);

  /**
   * Log warn.
   *
   * @param format format.
   * @param arg1 arg1.
   * @param obj2 arg2.
   * @since 1.0.0
   */
  void warn(String format, Object arg1, Object obj2);

  /**
   * Log warn.
   *
   * @param format format.
   * @param args var args.
   * @since 1.0.0
   */
  void warn(String format, Object... args);

  /**
   * Log warn.
   *
   * @param message message.
   * @param throwable throwable.
   * @since 1.0.0
   */
  void warn(String message, Throwable throwable);

  /**
   * Log error.
   *
   * @param message message.
   * @since 1.0.0
   */
  void error(Object message);

  /**
   * Log error.
   *
   * @param throwable throwable.
   * @since 1.0.0
   */
  void error(Throwable throwable);

  /**
   * Log error.
   *
   * @param format format.
   * @param obj1 arg1.
   * @since 1.0.0
   */
  void error(String format, Object obj1);

  /**
   * Log error.
   *
   * @param format format.
   * @param obj1 arg1.
   * @param obj2 arg2.
   * @since 1.0.0
   */
  void error(String format, Object obj1, Object obj2);

  /**
   * Log error.
   *
   * @param format format.
   * @param args var args.
   * @since 1.0.0
   */
  void error(String format, Object... args);

  /**
   * Log error.
   *
   * @param message message or format.
   * @param throwable throwable.
   * @since 1.0.0
   */
  void error(String message, Throwable throwable);
}

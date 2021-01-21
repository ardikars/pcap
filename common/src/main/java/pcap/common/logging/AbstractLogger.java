/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

/**
 * Abstract logger.
 *
 * @since 1.0.0
 */
abstract class AbstractLogger implements Logger {

  static final String UNKNOWN_LOG_LEVEL;
  static final String DEFAULT_FORMAT = "{}";
  static final String UNEXPECTED_EXCEPTION_MESSAGE;

  static {
    UNKNOWN_LOG_LEVEL = "Unknown log level";
    UNEXPECTED_EXCEPTION_MESSAGE =
        System.getProperty("pcap.common.logging.default", "Unexpected exception:");
  }

  private final String name;

  AbstractLogger(String name) {
    if (name == null || name.isEmpty()) {
      throw new IllegalArgumentException("Logger name should be not null or empty.");
    }
    this.name = name;
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public boolean isEnabled(LogLevel level) {
    switch (level) {
      case DEBUG:
        return isDebugEnabled();
      case INFO:
        return isInfoEnabled();
      case WARN:
        return isWarnEnabled();
      case ERROR:
        return isErrorEnabled();
      default:
        throw new Error(UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, Object format) {
    switch (level) {
      case DEBUG:
        debug(format);
        break;
      case INFO:
        info(format);
        break;
      case WARN:
        warn(format);
        break;
      case ERROR:
        error(format);
        break;
      default:
        throw new Error(UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, Throwable throwable) {
    switch (level) {
      case DEBUG:
        debug(throwable);
        break;
      case INFO:
        info(throwable);
        break;
      case WARN:
        warn(throwable);
        break;
      case ERROR:
        error(throwable);
        break;
      default:
        throw new Error(UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Object arg1) {
    switch (level) {
      case DEBUG:
        debug(format, arg1);
        break;
      case INFO:
        info(format, arg1);
        break;
      case WARN:
        warn(format, arg1);
        break;
      case ERROR:
        error(format, arg1);
        break;
      default:
        throw new Error(UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Object arg1, Object arg2) {
    switch (level) {
      case DEBUG:
        debug(format, arg1, arg2);
        break;
      case INFO:
        info(format, arg1, arg2);
        break;
      case WARN:
        warn(format, arg1, arg2);
        break;
      case ERROR:
        error(format, arg1, arg2);
        break;
      default:
        throw new Error(UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Object... args) {
    switch (level) {
      case DEBUG:
        debug(format, args);
        break;
      case INFO:
        info(format, args);
        break;
      case WARN:
        warn(format, args);
        break;
      case ERROR:
        error(format, args);
        break;
      default:
        throw new Error(UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Throwable throwable) {
    switch (level) {
      case DEBUG:
        debug(format, throwable);
        break;
      case INFO:
        info(format, throwable);
        break;
      case WARN:
        warn(format, throwable);
        break;
      case ERROR:
        error(format, throwable);
        break;
      default:
        throw new Error(UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void debug(Object message) {
    debug(DEFAULT_FORMAT, message);
  }

  @Override
  public void debug(Throwable throwable) {
    debug(UNEXPECTED_EXCEPTION_MESSAGE, throwable);
  }

  @Override
  public void info(Object message) {
    info(DEFAULT_FORMAT, message);
  }

  @Override
  public void info(Throwable throwable) {
    info(UNEXPECTED_EXCEPTION_MESSAGE, throwable);
  }

  @Override
  public void warn(Object message) {
    warn(DEFAULT_FORMAT, message);
  }

  @Override
  public void warn(Throwable throwable) {
    warn(UNEXPECTED_EXCEPTION_MESSAGE, throwable);
  }

  @Override
  public void error(Object message) {
    error(DEFAULT_FORMAT, message);
  }

  @Override
  public void error(Throwable throwable) {
    error(UNEXPECTED_EXCEPTION_MESSAGE, throwable);
  }
}

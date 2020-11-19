/** This code is licenced under the GPL version 2. */
package pcap.common.logging;

import org.apache.logging.log4j.spi.ExtendedLogger;
import org.apache.logging.log4j.spi.ExtendedLoggerWrapper;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
final class Log4j2Logger extends ExtendedLoggerWrapper implements Logger {

  public Log4j2Logger(org.apache.logging.log4j.Logger logger) {
    super((ExtendedLogger) logger, logger.getName(), logger.getMessageFactory());
  }

  @Override
  public String name() {
    return getName();
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
        throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, Object message) {
    switch (level) {
      case DEBUG:
        super.debug(message);
        break;
      case INFO:
        super.info(message);
        break;
      case WARN:
        super.warn(message);
        break;
      case ERROR:
        super.error(message);
        break;
      default:
        throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Object arg1) {
    switch (level) {
      case DEBUG:
        super.debug(format, arg1);
        break;
      case INFO:
        super.info(format, arg1);
        break;
      case WARN:
        super.warn(format, arg1);
        break;
      case ERROR:
        super.error(format, arg1);
        break;
      default:
        throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Object arg1, Object arg2) {
    switch (level) {
      case DEBUG:
        super.debug(format, arg1, arg2);
        break;
      case INFO:
        super.info(format, arg1, arg2);
        break;
      case WARN:
        super.warn(format, arg1, arg2);
        break;
      case ERROR:
        super.error(format, arg1, arg2);
        break;
      default:
        throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Object... args) {
    switch (level) {
      case DEBUG:
        super.debug(format, args);
        break;
      case INFO:
        super.info(format, args);
        break;
      case WARN:
        super.warn(format, args);
        break;
      case ERROR:
        super.error(format, args);
        break;
      default:
        throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, Throwable throwable) {
    switch (level) {
      case DEBUG:
        super.debug(throwable);
        break;
      case INFO:
        super.info(throwable);
        break;
      case WARN:
        super.warn(throwable);
        break;
      case ERROR:
        super.error(throwable);
        break;
      default:
        throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void log(LogLevel level, String format, Throwable throwable) {
    switch (level) {
      case DEBUG:
        super.debug(format, throwable);
        break;
      case INFO:
        super.info(format, throwable);
        break;
      case WARN:
        super.warn(format, throwable);
        break;
      case ERROR:
        super.error(format, throwable);
        break;
      default:
        throw new Error(AbstractLogger.UNKNOWN_LOG_LEVEL);
    }
  }

  @Override
  public void debug(Throwable throwable) {
    super.debug(throwable);
  }

  @Override
  public void info(Throwable throwable) {
    super.info(throwable);
  }

  @Override
  public void warn(Throwable throwable) {
    super.warn(throwable);
  }

  @Override
  public void error(Throwable throwable) {
    super.error(throwable);
  }
}

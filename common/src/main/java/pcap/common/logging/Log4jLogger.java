/** This code is licenced under the GPL version 2. */
package pcap.common.logging;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class Log4jLogger extends AbstractLogger {

  private final Logger logger;

  Log4jLogger(Logger logger) {
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
    return logger.isEnabledFor(Level.WARN);
  }

  @Override
  public boolean isErrorEnabled() {
    return logger.isEnabledFor(Level.ERROR);
  }

  @Override
  public void debug(String format, Object arg1) {
    FormattingTuple tuple = MessageFormatter.format(format, arg1);
    logger.debug(tuple.getMessage());
  }

  @Override
  public void debug(String format, Object arg1, Object arg2) {
    FormattingTuple tuple = MessageFormatter.format(format, arg1, arg2);
    logger.debug(tuple.getMessage());
  }

  @Override
  public void debug(String format, Object... args) {
    FormattingTuple tuple = MessageFormatter.format(format, args);
    logger.debug(tuple.getMessage());
  }

  @Override
  public void debug(String message, Throwable throwable) {
    logger.debug(message, throwable);
  }

  @Override
  public void info(String format, Object obj1) {
    FormattingTuple tuple = MessageFormatter.format(format, obj1);
    logger.info(tuple.getMessage());
  }

  @Override
  public void info(String format, Object obj1, Object obj2) {
    FormattingTuple tuple = MessageFormatter.format(format, obj1, obj2);
    logger.info(tuple.getMessage());
  }

  @Override
  public void info(String format, Object... args) {
    FormattingTuple tuple = MessageFormatter.format(format, args);
    logger.info(tuple.getMessage());
  }

  @Override
  public void info(String message, Throwable throwable) {
    logger.info(message, throwable);
  }

  @Override
  public void warn(String format, Object arg1) {
    FormattingTuple tuple = MessageFormatter.format(format, arg1);
    logger.info(tuple.getMessage());
  }

  @Override
  public void warn(String format, Object arg1, Object obj2) {
    FormattingTuple tuple = MessageFormatter.format(format, arg1, obj2);
    logger.warn(tuple.getMessage());
  }

  @Override
  public void warn(String format, Object... args) {
    FormattingTuple tuple = MessageFormatter.format(format, args);
    logger.warn(tuple.getMessage());
  }

  @Override
  public void warn(String message, Throwable throwable) {
    logger.warn(message, throwable);
  }

  @Override
  public void error(String format, Object obj1) {
    FormattingTuple tuple = MessageFormatter.format(format, obj1);
    logger.error(tuple.getMessage());
  }

  @Override
  public void error(String format, Object obj1, Object obj2) {
    FormattingTuple tuple = MessageFormatter.format(format, obj1, obj2);
    logger.error(tuple.getMessage());
  }

  @Override
  public void error(String format, Object... args) {
    FormattingTuple tuple = MessageFormatter.format(format, args);
    logger.error(tuple.getMessage());
  }

  @Override
  public void error(String message, Throwable throwable) {
    logger.error(message, throwable);
  }
}

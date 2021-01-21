/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.logging;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.function.Executable;

/** */
abstract class AbstractLoggerTest {

  private static final String DEFAULT_NAME = "LoggeTest";

  private static final String DEFAULT_FORMAT_ONE = "Hello {}";

  private static final String DEFAULT_FORMAT_TWO = "Hello {} {}";

  private static final String DEFAULT_FORMAT_THREE = "Hello {} {} {}";

  private static final String DEFAULT_MESSAGE_ONE = "Java";

  private static final String DEFAULT_MESSAGE_TWO = "World";

  private static final String DEFAULT_MESSAGE_THREE = "Game";

  private Logger logger;

  public abstract void initLogger();

  protected void doInitLogger(LoggerFactory loggerFactory) {
    logger = loggerFactory.newInstance(DEFAULT_NAME);
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            new TestLogger(null);
          }
        });
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            new TestLogger("");
          }
        });
  }

  public abstract void nameTest();

  protected void doNameTest() {
    assert logger.name().equals(DEFAULT_NAME) || logger.name().equals("NOP");
  }

  public abstract void isEnabledTest();

  protected void doIsEnabledTest() {
    assert logger.isEnabled(LogLevel.DEBUG) || !logger.isEnabled(LogLevel.DEBUG);
    assert logger.isEnabled(LogLevel.ERROR) || !logger.isEnabled(LogLevel.ERROR);
    assert logger.isEnabled(LogLevel.WARN) || !logger.isEnabled(LogLevel.WARN);
    assert logger.isEnabled(LogLevel.INFO) || !logger.isEnabled(LogLevel.INFO);
    Assertions.assertThrows(
        Error.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            logger.isEnabled(LogLevel.UNKNOWN);
          }
        });
  }

  public abstract void isDebugEnabledTest();

  protected void doIsDebugEnabledTest() {
    assert logger.isDebugEnabled() || !logger.isDebugEnabled();
  }

  public abstract void isInfoEnabledTest();

  protected void doIsInfoEnabledTest() {
    assert logger.isInfoEnabled() || !logger.isInfoEnabled();
  }

  public abstract void isWarnEnabledTest();

  protected void doIsWarnEnabledTest() {
    assert logger.isWarnEnabled() || !logger.isWarnEnabled();
  }

  public abstract void isErrorEnabledTest();

  protected void doIsErrorEnabledTest() {
    assert logger.isErrorEnabled() || !logger.isErrorEnabled();
  }

  public abstract void logLavelAndMessageTest();

  protected void doLogLavelAndMessageTest() {
    logger.log(LogLevel.DEBUG, DEFAULT_MESSAGE_ONE);
    logger.log(LogLevel.ERROR, DEFAULT_MESSAGE_ONE);
    logger.log(LogLevel.WARN, DEFAULT_MESSAGE_ONE);
    logger.log(LogLevel.INFO, DEFAULT_MESSAGE_ONE);
    Assertions.assertThrows(
        Error.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            logger.log(LogLevel.UNKNOWN, DEFAULT_MESSAGE_ONE);
          }
        });
  }

  public abstract void logLevelAndMessageFormatOneTest();

  protected void doLogLevelAndMessageFormatOneTest() {
    logger.log(LogLevel.DEBUG, DEFAULT_FORMAT_ONE, DEFAULT_MESSAGE_ONE);
    logger.log(LogLevel.ERROR, DEFAULT_FORMAT_ONE, DEFAULT_MESSAGE_ONE);
    logger.log(LogLevel.WARN, DEFAULT_FORMAT_ONE, DEFAULT_MESSAGE_ONE);
    logger.log(LogLevel.INFO, DEFAULT_FORMAT_ONE, DEFAULT_MESSAGE_ONE);
    Assertions.assertThrows(
        Error.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            logger.log(LogLevel.UNKNOWN, DEFAULT_FORMAT_ONE, DEFAULT_MESSAGE_ONE);
          }
        });
  }

  public abstract void logLevelAndMessageFormatTwoTest();

  protected void doLogLevelAndMessageFormatTwoTest() {
    logger.log(LogLevel.DEBUG, DEFAULT_FORMAT_TWO, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO);
    logger.log(LogLevel.ERROR, DEFAULT_FORMAT_TWO, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO);
    logger.log(LogLevel.WARN, DEFAULT_FORMAT_TWO, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO);
    logger.log(LogLevel.INFO, DEFAULT_FORMAT_TWO, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO);
    Assertions.assertThrows(
        Error.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            logger.log(
                LogLevel.UNKNOWN, DEFAULT_FORMAT_TWO, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO);
          }
        });
  }

  public abstract void logLevelAndMessageFormatThreeTest();

  protected void doLogLevelAndMessageFormatThreeTest() {
    logger.log(
        LogLevel.DEBUG,
        DEFAULT_FORMAT_THREE,
        DEFAULT_MESSAGE_ONE,
        DEFAULT_MESSAGE_TWO,
        DEFAULT_MESSAGE_THREE);
    logger.log(
        LogLevel.ERROR,
        DEFAULT_FORMAT_THREE,
        DEFAULT_MESSAGE_ONE,
        DEFAULT_MESSAGE_TWO,
        DEFAULT_MESSAGE_THREE);
    logger.log(
        LogLevel.WARN,
        DEFAULT_FORMAT_THREE,
        DEFAULT_MESSAGE_ONE,
        DEFAULT_MESSAGE_TWO,
        DEFAULT_MESSAGE_THREE);
    logger.log(
        LogLevel.INFO,
        DEFAULT_FORMAT_THREE,
        DEFAULT_MESSAGE_ONE,
        DEFAULT_MESSAGE_TWO,
        DEFAULT_MESSAGE_THREE);
    Assertions.assertThrows(
        Error.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            logger.log(
                LogLevel.UNKNOWN,
                DEFAULT_FORMAT_THREE,
                DEFAULT_MESSAGE_ONE,
                DEFAULT_MESSAGE_TWO,
                DEFAULT_MESSAGE_THREE);
          }
        });
  }

  public abstract void logLevelAndThrowableTest();

  protected void doLogLevelAndThrowableTest() {
    logger.log(LogLevel.DEBUG, new Throwable("Log some error here"));
    logger.log(LogLevel.ERROR, new Throwable("Log some error here"));
    logger.log(LogLevel.WARN, new Throwable("Log some error here"));
    logger.log(LogLevel.INFO, new Throwable("Log some error here"));
    Assertions.assertThrows(
        Error.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            logger.log(LogLevel.UNKNOWN, new Throwable("Log some error here"));
          }
        });
  }

  public abstract void logLevelAndMessageThrowableTest();

  protected void doLogLevelAndMessageThrowableTest() {
    logger.log(LogLevel.DEBUG, DEFAULT_MESSAGE_ONE, new Throwable("Log some error here"));
    logger.log(LogLevel.ERROR, DEFAULT_MESSAGE_ONE, new Throwable("Log some error here"));
    logger.log(LogLevel.WARN, DEFAULT_MESSAGE_ONE, new Throwable("Log some error here"));
    logger.log(LogLevel.INFO, DEFAULT_MESSAGE_ONE, new Throwable("Log some error here"));
    Assertions.assertThrows(
        Error.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            logger.log(LogLevel.UNKNOWN, DEFAULT_MESSAGE_ONE, new Throwable("Log some error here"));
          }
        });
  }

  public abstract void debugMessageOneTest();

  protected void doDebugMessageOneTest() {
    logger.debug(DEFAULT_MESSAGE_ONE);
  }

  public abstract void debugThrowableTest();

  protected void doDebugThrowableTest() {
    logger.debug(new Throwable("Log some error here"));
  }

  public abstract void debugMessageFormatOneTest();

  protected void doDebugMessageFormatOneTest() {
    logger.debug(DEFAULT_FORMAT_ONE, DEFAULT_MESSAGE_ONE);
  }

  public abstract void debugMessageFormatTwoTest();

  protected void doDebugMessageFormatTwoTest() {
    logger.debug(DEFAULT_FORMAT_TWO, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO);
  }

  public abstract void debugMessageFormatThreeTest();

  protected void doDebugMessageFormatThreeTest() {
    logger.debug(
        DEFAULT_FORMAT_THREE, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO, DEFAULT_MESSAGE_THREE);
  }

  public abstract void debugMessageThrowableTest();

  protected void doDebugMessageThrowableTest() {
    logger.debug(DEFAULT_MESSAGE_ONE, new Throwable("Log some error here"));
  }

  public abstract void errorMessageOneTest();

  protected void doErrorMessageOneTest() {
    logger.error(DEFAULT_MESSAGE_ONE);
  }

  public abstract void errorThrowableTest();

  protected void doErrorThrowableTest() {
    logger.error(new Throwable("Log some error here"));
  }

  public abstract void errorMessageFormatOneTest();

  protected void doErrorMessageFormatOneTest() {
    logger.error(DEFAULT_FORMAT_ONE, DEFAULT_MESSAGE_ONE);
  }

  public abstract void errorMessageFormatTwoTest();

  protected void doErrorMessageFormatTwoTest() {
    logger.error(DEFAULT_FORMAT_TWO, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO);
  }

  public abstract void errorMessageFormatThreeTest();

  protected void doErrorMessageFormatThreeTest() {
    logger.error(
        DEFAULT_FORMAT_THREE, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO, DEFAULT_MESSAGE_THREE);
  }

  public abstract void errorMessageThrowableTest();

  protected void doErrorMessageThrowableTest() {
    logger.error(DEFAULT_MESSAGE_ONE, new Throwable("Log some error here"));
  }

  public abstract void warnMessageOneTest();

  protected void doWarnMessageOneTest() {
    logger.warn(DEFAULT_MESSAGE_ONE);
  }

  public abstract void warnThrowableTest();

  protected void doWarnThrowableTest() {
    logger.warn(new Throwable("Log some error here"));
  }

  public abstract void warnMessageFormatOneTest();

  protected void doWarnMessageFormatOneTest() {
    logger.warn(DEFAULT_FORMAT_ONE, DEFAULT_MESSAGE_ONE);
  }

  public abstract void warnMessageFormatTwoTest();

  protected void doWarnMessageFormatTwoTest() {
    logger.warn(DEFAULT_FORMAT_TWO, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO);
  }

  public abstract void warnMessageFormatThreeTest();

  protected void doWarnMessageFormatThreeTest() {
    logger.warn(
        DEFAULT_FORMAT_THREE, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO, DEFAULT_MESSAGE_THREE);
  }

  public abstract void warnMessageThrowableTest();

  protected void doWarnMessageThrowableTest() {
    logger.warn(DEFAULT_MESSAGE_ONE, new Throwable("Log some error here"));
  }

  public abstract void infoMessageOneTest();

  protected void doInfoMessageOneTest() {
    logger.info(DEFAULT_MESSAGE_ONE);
  }

  public abstract void infoThrowableTest();

  protected void doInfoThrowableTest() {
    logger.info(new Throwable("Log some error here"));
  }

  public abstract void infoMessageFormatOneTest();

  protected void doInfoMessageFormatOneTest() {
    logger.info(DEFAULT_FORMAT_ONE, DEFAULT_MESSAGE_ONE);
  }

  public abstract void infoMessageFormatTwoTest();

  protected void doInfoMessageFormatTwoTest() {
    logger.info(DEFAULT_FORMAT_TWO, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO);
  }

  public abstract void infoMessageFormatThreeTest();

  protected void doInfoMessageFormatThreeTest() {
    logger.info(
        DEFAULT_FORMAT_THREE, DEFAULT_MESSAGE_ONE, DEFAULT_MESSAGE_TWO, DEFAULT_MESSAGE_THREE);
  }

  public abstract void infoMessageThrowableTest();

  protected void doInfoMessageThrowableTest() {
    logger.info(DEFAULT_MESSAGE_ONE, new Throwable("Log some error here"));
  }

  static final class TestLogger extends AbstractLogger {

    TestLogger(String name) {
      super(name);
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
    public void debug(String format, Object arg1) {}

    @Override
    public void debug(String format, Object arg1, Object arg2) {}

    @Override
    public void debug(String format, Object... args) {}

    @Override
    public void debug(String message, Throwable throwable) {}

    @Override
    public void info(String format, Object obj1) {}

    @Override
    public void info(String format, Object obj1, Object obj2) {}

    @Override
    public void info(String format, Object... args) {}

    @Override
    public void info(String message, Throwable throwable) {}

    @Override
    public void warn(String format, Object arg1) {}

    @Override
    public void warn(String format, Object arg1, Object obj2) {}

    @Override
    public void warn(String format, Object... args) {}

    @Override
    public void warn(String message, Throwable throwable) {}

    @Override
    public void error(String format, Object obj1) {}

    @Override
    public void error(String format, Object obj1, Object obj2) {}

    @Override
    public void error(String format, Object... args) {}

    @Override
    public void error(String message, Throwable throwable) {}
  }
}

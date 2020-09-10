package pcap.common.logging;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

// @ExtendWith(MockitoExtension.class)
@RunWith(JUnitPlatform.class)
public class LoggerFactoryTest {

  @Test
  public void hasClassTest() {
    Assertions.assertTrue(LoggerFactory.hasClass("org.apache.logging.log4j.LogManager"));
    Assertions.assertTrue(LoggerFactory.hasClass("org.slf4j.LoggerFactory"));
    Assertions.assertFalse(LoggerFactory.hasClass("pcap.LoggerFactory"));
  }

  // @Test
  public void sl4jLoggerTest() {
    try (MockedStatic<Slf4jLoggerFactory> theMock = Mockito.mockStatic(Slf4jLoggerFactory.class)) {
      theMock.when(Slf4jLoggerFactory::hasSlf4j).thenReturn(true);
      Assertions.assertTrue(Slf4jLoggerFactory.hasSlf4j());
      Assertions.assertTrue(
          LoggerFactory.getLogger(LoggerFactory.class.getSimpleName()) instanceof Slf4jLogger);
      Assertions.assertTrue(LoggerFactory.getLogger(LoggerFactory.class) instanceof Slf4jLogger);
      Assertions.assertTrue(LoggerFactory.getLogger(this) instanceof Slf4jLogger);
    }
  }

  // @Test
  public void log4j2LoggerTest() {
    try (MockedStatic<Slf4jLoggerFactory> theMock = Mockito.mockStatic(Slf4jLoggerFactory.class)) {
      theMock.when(Slf4jLoggerFactory::hasSlf4j).thenReturn(false);
      Assertions.assertFalse(Slf4jLoggerFactory.hasSlf4j());
      Assertions.assertTrue(
          LoggerFactory.getLogger(LoggerFactory.class.getSimpleName()) instanceof Log4j2Logger);
      Assertions.assertTrue(LoggerFactory.getLogger(LoggerFactory.class) instanceof Log4j2Logger);
      Assertions.assertTrue(LoggerFactory.getLogger(this) instanceof Log4j2Logger);
    }
  }

  // @Test
  public void noLoggerTest() {
    try (MockedStatic<Slf4jLoggerFactory> slf4jMock =
        Mockito.mockStatic(Slf4jLoggerFactory.class)) {
      try (MockedStatic<Log4j2LoggerFactory> log4j2Mock =
          Mockito.mockStatic(Log4j2LoggerFactory.class)) {
        slf4jMock.when(Slf4jLoggerFactory::hasSlf4j).thenReturn(false);
        log4j2Mock.when(Log4j2LoggerFactory::hasLog4j2).thenReturn(false);
        Assertions.assertFalse(Slf4jLoggerFactory.hasSlf4j());
        Assertions.assertFalse(Log4j2LoggerFactory.hasLog4j2());
        Assertions.assertTrue(
            LoggerFactory.getLogger(LoggerFactory.class.getSimpleName()) instanceof NoLogger);
        Assertions.assertTrue(LoggerFactory.getLogger(LoggerFactory.class) instanceof NoLogger);
        Assertions.assertTrue(LoggerFactory.getLogger(this) instanceof NoLogger);
      }
    }
  }
}

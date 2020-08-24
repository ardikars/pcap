package pcap.common.logging;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class LoggerFactoryTest {

  @Test
  public void hasClassTest() {
    Assertions.assertTrue(LoggerFactory.hasClass("org.apache.logging.log4j.LogManager"));
    Assertions.assertTrue(LoggerFactory.hasClass("org.slf4j.LoggerFactory"));
    Assertions.assertFalse(LoggerFactory.hasClass("pcap.LoggerFactory"));
  }

  @Test
  public void getLoggerTestTest() {
    Assertions.assertNotNull(LoggerFactory.getLogger(LoggerFactory.class.getSimpleName()));
    Assertions.assertNotNull(LoggerFactory.getLogger(LoggerFactory.class));
    Assertions.assertNotNull(LoggerFactory.getLogger(this));
  }
}

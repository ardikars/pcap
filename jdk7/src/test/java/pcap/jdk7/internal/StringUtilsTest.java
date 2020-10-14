package pcap.jdk7.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class StringUtilsTest {

  @Test
  public void emptyTest() {
    Assertions.assertTrue(StringUtils.empty(null));
    Assertions.assertTrue(StringUtils.empty(""));
  }

  @Test
  public void blankTest() {
    Assertions.assertTrue(StringUtils.blank(" "));
    Assertions.assertTrue(StringUtils.blank(null));
    Assertions.assertTrue(StringUtils.blank("\t "));
    Assertions.assertTrue(StringUtils.blank("\r "));
    Assertions.assertTrue(StringUtils.blank("\n "));
    Assertions.assertTrue(StringUtils.blank("\0 "));
    Assertions.assertFalse(StringUtils.blank("abc"));
  }
}

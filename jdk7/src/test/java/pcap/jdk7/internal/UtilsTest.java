package pcap.jdk7.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class UtilsTest {

  @Test
  public void emptyTest() {
    Assertions.assertTrue(Utils.empty(null));
    Assertions.assertTrue(Utils.empty(""));
  }

  @Test
  public void blankTest() {
    Assertions.assertTrue(Utils.blank(" "));
    Assertions.assertTrue(Utils.blank(null));
    Assertions.assertTrue(Utils.blank("\t "));
    Assertions.assertTrue(Utils.blank("\r "));
    Assertions.assertTrue(Utils.blank("\n "));
    Assertions.assertTrue(Utils.blank("\0 "));
    Assertions.assertFalse(Utils.blank("abc"));
  }
}

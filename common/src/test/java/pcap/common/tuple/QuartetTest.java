/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class QuartetTest extends BaseTest {

  @Test
  public void quartet() {
    Quartet<Integer, Float, Long, String> quartet = Tuple.of(1, 1.1F, 1L, "nol");
    Assertions.assertEquals(Integer.valueOf(1), quartet.left());
    Assertions.assertEquals(Float.valueOf(1.1F), quartet.middleLeft());
    Assertions.assertEquals(Long.valueOf(1L), quartet.middleRight());
    Assertions.assertEquals("nol", quartet.right());
  }
}

/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class QuintetTest extends BaseTest {

  @Test
  public void quintet() {
    Quintet<Integer, Float, Long, Double, String> quintet = Tuple.of(1, 1.1F, 1L, 1.1D, "nol");
    Assertions.assertEquals(Integer.valueOf(1), quintet.left());
    Assertions.assertEquals(Float.valueOf(1.1F), quintet.betweenLeftAndMiddle());
    Assertions.assertEquals(Long.valueOf(1L), quintet.middle());
    Assertions.assertEquals(Double.valueOf(1.1D), quintet.betweenRigthAndMiddle());
    Assertions.assertEquals("nol", quintet.right());
  }
}

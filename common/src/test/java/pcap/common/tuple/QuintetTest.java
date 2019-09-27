/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class QuintetTest extends BaseTest {

  @Test
  public void quintet() {
    Quintet<Integer, Float, Long, Double, String> quintet = Tuple.of(1, 1.1F, 1L, 1.1D, "nol");
    Assertions.assertEquals(Integer.valueOf(1), quintet.getLeft());
    Assertions.assertEquals(Float.valueOf(1.1F), quintet.getBetweenLeftAndMiddle());
    Assertions.assertEquals(Long.valueOf(1L), quintet.getMiddle());
    Assertions.assertEquals(Double.valueOf(1.1D), quintet.getBetweenRigthAndMiddle());
    Assertions.assertEquals("nol", quintet.getRight());
  }
}

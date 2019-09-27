/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class TripletTest extends BaseTest {

  @Test
  public void triplet() {
    Triplet<Integer, Double, String> triplet = Tuple.of(1, 0.3, "nol");
    Assertions.assertEquals(Integer.valueOf(1), triplet.getLeft());
    Assertions.assertEquals(Double.valueOf(0.3), triplet.getMiddle());
    Assertions.assertEquals("nol", triplet.getRight());
  }
}

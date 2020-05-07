/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class TripletTest extends BaseTest {

  @Test
  public void triplet() {
    Triplet<Integer, Double, String> triplet = Tuple.of(1, 0.3, "nol");
    Assertions.assertEquals(Integer.valueOf(1), triplet.left());
    Assertions.assertEquals(Double.valueOf(0.3), triplet.middle());
    Assertions.assertEquals("nol", triplet.right());
  }
}

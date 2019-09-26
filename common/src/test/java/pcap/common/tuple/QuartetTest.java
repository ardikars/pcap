/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class QuartetTest extends BaseTest {

  @Test
  public void quartet() {
    Quartet<Integer, Float, Long, String> quartet = Tuple.of(1, 1.1F, 1L, "nol");
    Assertions.assertEquals(Integer.valueOf(1), quartet.getLeft());
    Assertions.assertEquals(Float.valueOf(1.1F), quartet.getMiddleLeft());
    Assertions.assertEquals(Integer.valueOf(1), quartet.getLeft());
    Assertions.assertEquals(Integer.valueOf(1), quartet.getLeft());
  }
}

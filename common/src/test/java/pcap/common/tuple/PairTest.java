/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PairTest extends BaseTest {

  @Test
  public void pair() {
    Pair<Integer, String> pair = Tuple.of(1, "nol");
    Assertions.assertEquals(Integer.valueOf(1), pair.getLeft());
    Assertions.assertEquals("nol", pair.getRight());
  }
}

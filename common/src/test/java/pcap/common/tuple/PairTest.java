/** This code is licenced under the GPL version 2. */
package pcap.common.tuple;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class PairTest extends BaseTest {

  @Test
  public void pair() {
    Pair<Integer, String> pair = Tuple.of(1, "nol");
    Assertions.assertEquals(Integer.valueOf(1), pair.left());
    Assertions.assertEquals("nol", pair.right());
  }
}

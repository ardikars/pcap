/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public class ObjectsTest {

  @Test
  public void nonNullTest() {
    Assertions.assertTrue(Objects.nonNull(""));
  }
}

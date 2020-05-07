/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.util.HashSet;
import java.util.LinkedHashSet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class SetsTest {

  @Test
  public void createHashSetTest() {
    Assertions.assertTrue(Sets.createHashSet(10) instanceof HashSet);
  }

  @Test
  public void createLinkedHashSetTest() {
    Assertions.assertTrue(Sets.createLinkedHashSet(10) instanceof LinkedHashSet);
  }
}

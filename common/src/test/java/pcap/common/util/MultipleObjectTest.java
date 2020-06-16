package pcap.common.util;

import java.io.Serializable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class MultipleObjectTest {

  @Test
  public void buildTest() {
    MultipleObject<? extends Serializable> firstMultipleObjects = MultipleObject.of("1", 2);
    MultipleObject<? extends Serializable> secondMultipleObjects = MultipleObject.of("1", 2);
    Assertions.assertEquals(firstMultipleObjects, secondMultipleObjects);
    Assertions.assertEquals(firstMultipleObjects.hashCode(), secondMultipleObjects.hashCode());
    Assertions.assertFalse(firstMultipleObjects.equals(""));
    Assertions.assertFalse(firstMultipleObjects.equals(null));
    Assertions.assertTrue(firstMultipleObjects.equals(firstMultipleObjects));
    Assertions.assertTrue(firstMultipleObjects.equals(secondMultipleObjects));
  }

  @Test
  public void toStringTest() {
    Assertions.assertNotNull(MultipleObject.of("1", 2).toString());
  }
}

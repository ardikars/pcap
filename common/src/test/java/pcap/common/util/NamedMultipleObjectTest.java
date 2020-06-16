package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class NamedMultipleObjectTest {

  @Test
  public void buildTest() {
    IcmpTypeAndCode first =
        new IcmpTypeAndCode(MultipleObject.of((byte) 1, (byte) 0), "No route to destination");
    IcmpTypeAndCode second =
        new IcmpTypeAndCode(MultipleObject.of((byte) 1, (byte) 0), "No route to destination");

    Assertions.assertEquals(first, second);
    Assertions.assertEquals(first.hashCode(), second.hashCode());
    Assertions.assertFalse(first.equals(""));
    Assertions.assertFalse(first.equals(null));
    Assertions.assertTrue(first.equals(first));
    Assertions.assertTrue(first.equals(second));
  }

  @Test
  public void toStringTest() {
    Assertions.assertNotNull(
        new IcmpTypeAndCode(MultipleObject.of((byte) 1, (byte) 0), "No route to destination")
            .toString());
  }

  static class IcmpTypeAndCode extends NamedMultipleObject<MultipleObject<Byte>, IcmpTypeAndCode> {

    protected IcmpTypeAndCode(MultipleObject<Byte> multiKey, String name) {
      super(multiKey, name);
    }
  }
}

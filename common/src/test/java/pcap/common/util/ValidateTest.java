/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class ValidateTest {

  @Test
  public void nullPointerTest() {
    Validate.nullPointer("");
    Assertions.assertThrows(NullPointerException.class, () -> Validate.nullPointer(null));
    Validate.nullPointer("", "OK");
    Assertions.assertThrows(NullPointerException.class, () -> Validate.nullPointer(null, "NOK"));
    Assertions.assertEquals("OK", Validate.nullPointerThenReturns(null, "OK"));
  }

  @Test
  public void notIllegalArgumentTest() {
    Validate.notIllegalArgument(true);
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notIllegalArgument(false));
    Validate.notIllegalArgument(true, "OK");
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notIllegalArgument(false, "NOK"));
    Assertions.assertEquals("OK", Validate.notIllegalArgumentThenReturns(false, "NOK", "OK"));
    Assertions.assertEquals("OK", Validate.notIllegalArgumentThenReturns(true, "OK", "NOK"));
  }

  @Test
  public void notIllegalStateTest() {
    Validate.notIllegalState(true);
    Assertions.assertThrows(IllegalStateException.class, () -> Validate.notIllegalState(false));
    Validate.notIllegalState(true, "OK");
    Assertions.assertThrows(
        IllegalStateException.class, () -> Validate.notIllegalState(false, "NOK"));
    Assertions.assertEquals("OK", Validate.notIllegaStateThenReturns(false, "NOK", "OK"));
    Assertions.assertEquals("OK", Validate.notIllegaStateThenReturns(true, "OK", "NOK"));
  }
}

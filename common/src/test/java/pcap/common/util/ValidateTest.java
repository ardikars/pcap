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
    Assertions.assertEquals("YES", Validate.nullPointerThenReturns("YES", "OK"));
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

  @Test
  public void notInBoundsTestBytes() {
    byte[] data = new byte[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notInBounds(new byte[0], 0, 3));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, -1, 5));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 6, 5));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 0));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, -1));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 6));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 5, 5));

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestChars() {
    char[] data = new char[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notInBounds(new char[0], 0, 3));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, -1, 5));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 6, 5));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 0));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, -1));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 6));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 5, 5));

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestShorts() {
    short[] data = new short[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notInBounds(new short[0], 0, 3));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, -1, 5));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 6, 5));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 0));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, -1));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 6));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 5, 5));

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestInts() {
    int[] data = new int[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notInBounds(new int[0], 0, 3));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, -1, 5));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 6, 5));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 0));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, -1));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 6));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 5, 5));

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestFloats() {
    float[] data = new float[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notInBounds(new float[0], 0, 3));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, -1, 5));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 6, 5));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 0));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, -1));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 6));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 5, 5));

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestLongs() {
    long[] data = new long[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notInBounds(new long[0], 0, 3));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, -1, 5));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 6, 5));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 0));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, -1));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 6));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 5, 5));

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestDoubles() {
    double[] data = new double[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notInBounds(new double[0], 0, 3));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, -1, 5));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 6, 5));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 0));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, -1));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 6));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 5, 5));

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTestObjects() {
    Object[] data = new Object[] {0, 1, 2, 3, 4};
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> Validate.notInBounds(new Object[0], 0, 3));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, -1, 5));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 6, 5));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 0));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, -1));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 6));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 5, 5));

    Validate.notInBounds(data, 0, 5);
  }

  @Test
  public void notInBoundsTest() {
    int data = 5;
    Assertions.assertThrows(IllegalArgumentException.class, () -> Validate.notInBounds(0, 0, 3));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, -1, 5));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 6, 5));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 0));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, -1));
    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 0, 6));

    Assertions.assertThrows(
        IndexOutOfBoundsException.class, () -> Validate.notInBounds(data, 5, 5));

    Validate.notInBounds(data, 0, 5);
  }
}

/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@RunWith(JUnitPlatform.class)
public class ArraysTest extends BaseTest {

  private final int maximumDelta = 2;

  private final byte[] byteArray = new byte[] {0, 1, 2, 3, 4};

  private final char[] charArray = new char[] {0, 'B', 'A', 3, 4};

  private final short[] shortArray = new short[] {0, 1, 2, 3, 4};

  private final int[] intArray = new int[] {0, 1, 2, 3, 4};

  private final float[] floatArray =
      new float[] {(float) 0.0, (float) 0.1, (float) 0.2, (float) 0.3, (float) 0.4};

  private final long[] longArray = new long[] {0, 1, 2, 3, 4};

  private final double[] doubleArray = new double[] {0.0, 0.1, 0.2, 0.3, 0.4};

  private final Object[] objectArray = new Object[] {charArray, doubleArray};

  @Test
  public void reserveByteArray() {
    assertArrayEquals(new byte[] {4, 3, 2, 1, 0}, Arrays.reverse(byteArray));
  }

  @Test
  public void reserveCharArray() {
    assertArrayEquals(new char[] {4, 3, 'A', 'B', 0}, Arrays.reverse(charArray));
  }

  @Test
  public void reserveShortArray() {
    assertArrayEquals(new short[] {4, 3, 2, 1, 0}, Arrays.reverse(shortArray));
  }

  @Test
  public void reserveIntArray() {
    assertArrayEquals(new int[] {4, 3, 2, 1, 0}, Arrays.reverse(intArray));
  }

  @Test
  public void reserveFloatArray() {
    assertArrayEquals(
        new float[] {(float) 0.4, (float) 0.3, (float) 0.2, (float) 0.1, (float) 0.0},
        Arrays.reverse(floatArray),
        maximumDelta);
  }

  @Test
  public void reserveLongArray() {
    assertArrayEquals(new long[] {4, 3, 2, 1, 0}, Arrays.reverse(longArray));
  }

  @Test
  public void reserveDoubleArray() {
    assertArrayEquals(
        new double[] {0.4, 0.3, 0.2, 0.1, 0.0}, Arrays.reverse(doubleArray), maximumDelta);
  }

  @Test
  public void reserveObjectArray() {
    assertArrayEquals(new Object[] {doubleArray, charArray}, Arrays.reverse(objectArray));
  }

  @Test
  public void concatenateByte() {
    assertArrayEquals(
        new byte[] {0, 1, 2, 3, 4, 5, 6}, Arrays.concatenate(new byte[][] {byteArray, {5, 6}}));
  }

  @Test
  public void concatenateChar() {
    assertArrayEquals(
        new char[] {0, 'B', 'A', 3, 4, 5, 6}, Arrays.concatenate(new char[][] {charArray, {5, 6}}));
  }

  @Test
  public void concatenateShort() {
    assertArrayEquals(
        new short[] {0, 1, 2, 3, 4, 5, 6}, Arrays.concatenate(new short[][] {shortArray, {5, 6}}));
  }

  @Test
  public void concatenateInt() {
    assertArrayEquals(
        new int[] {0, 1, 2, 3, 4, 5, 6}, Arrays.concatenate(new int[][] {intArray, {5, 6}}));
  }

  @Test
  public void concatenateFloat() {
    assertArrayEquals(
        new float[] {
          (float) 0.0, (float) 0.1, (float) 0.2, (float) 0.3, (float) 0.4, (float) 0.5, (float) 0.6
        },
        Arrays.concatenate(new float[][] {floatArray, {(float) 0.5, (float) 0.6}}),
        maximumDelta);
  }

  @Test
  public void concatenateLong() {
    assertArrayEquals(
        new long[] {0, 1, 2, 3, 4, 5, 6}, Arrays.concatenate(longArray, new long[] {5, 6}));
  }

  @Test
  public void concatenateDouble() {
    assertArrayEquals(
        new double[] {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6},
        Arrays.concatenate(doubleArray, new double[] {0.5, 0.6}),
        maximumDelta);
  }

  @Test
  public void concatenateObject() {
    assertArrayEquals(
        new Object[] {charArray, doubleArray, intArray, floatArray},
        Arrays.concatenate(objectArray, new Object[] {intArray, floatArray}));
  }

  @Test
  public void toStringTest() {
    String string = Arrays.toString(new int[] {1, 2});
    assertNotNull(string);
  }
}

/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @since 1.0.0
 */
class ArraysTest {

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
  void reserveByteArray() {
    assertArrayEquals(new byte[] {4, 3, 2, 1, 0}, Arrays.reverse(byteArray));
  }

  @Test
  void reserveCharArray() {
    assertArrayEquals(new char[] {4, 3, 'A', 'B', 0}, Arrays.reverse(charArray));
  }

  @Test
  void reserveShortArray() {
    assertArrayEquals(new short[] {4, 3, 2, 1, 0}, Arrays.reverse(shortArray));
  }

  @Test
  void reserveIntArray() {
    assertArrayEquals(new int[] {4, 3, 2, 1, 0}, Arrays.reverse(intArray));
  }

  @Test
  void reserveFloatArray() {
    assertArrayEquals(
        new float[] {(float) 0.4, (float) 0.3, (float) 0.2, (float) 0.1, (float) 0.0},
        Arrays.reverse(floatArray),
        maximumDelta);
  }

  @Test
  void reserveLongArray() {
    assertArrayEquals(new long[] {4, 3, 2, 1, 0}, Arrays.reverse(longArray));
  }

  @Test
  void reserveDoubleArray() {
    assertArrayEquals(
        new double[] {0.4, 0.3, 0.2, 0.1, 0.0}, Arrays.reverse(doubleArray), maximumDelta);
  }

  @Test
  void reserveObjectArray() {
    assertArrayEquals(new Object[] {doubleArray, charArray}, Arrays.reverse(objectArray));
  }

  @Test
  void concatenateByte() {
    assertArrayEquals(
        new byte[] {0, 1, 2, 3, 4, 5, 6}, Arrays.concatenate(new byte[][] {byteArray, {5, 6}}));
  }

  @Test
  void concatenateChar() {
    assertArrayEquals(
        new char[] {0, 'B', 'A', 3, 4, 5, 6}, Arrays.concatenate(new char[][] {charArray, {5, 6}}));
  }

  @Test
  void concatenateShort() {
    assertArrayEquals(
        new short[] {0, 1, 2, 3, 4, 5, 6}, Arrays.concatenate(new short[][] {shortArray, {5, 6}}));
  }

  @Test
  void concatenateInt() {
    assertArrayEquals(
        new int[] {0, 1, 2, 3, 4, 5, 6}, Arrays.concatenate(new int[][] {intArray, {5, 6}}));
  }

  @Test
  void concatenateFloat() {
    assertArrayEquals(
        new float[] {
          (float) 0.0, (float) 0.1, (float) 0.2, (float) 0.3, (float) 0.4, (float) 0.5, (float) 0.6
        },
        Arrays.concatenate(new float[][] {floatArray, {(float) 0.5, (float) 0.6}}),
        maximumDelta);
  }

  @Test
  void concatenateLong() {
    assertArrayEquals(
        new long[] {0, 1, 2, 3, 4, 5, 6}, Arrays.concatenate(longArray, new long[] {5, 6}));
  }

  @Test
  void concatenateDouble() {
    assertArrayEquals(
        new double[] {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6},
        Arrays.concatenate(doubleArray, new double[] {0.5, 0.6}),
        maximumDelta);
  }

  @Test
  void concatenateObject() {
    assertArrayEquals(
        new Object[] {charArray, doubleArray, intArray, floatArray},
        Arrays.concatenate(objectArray, new Object[] {intArray, floatArray}));
  }

  @Test
  void toStringTest() {
    String string = Arrays.toString(new int[] {1, 2});
    Assertions.assertNotNull(string);
  }
}

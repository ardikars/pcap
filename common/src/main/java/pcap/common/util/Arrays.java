/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.common.util;

import java.lang.reflect.Array;
import java.util.Collections;
import java.util.List;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public final class Arrays {

  private Arrays() {}

  /**
   * Reverse order.
   *
   * @param value value.
   * @return array in reverse order.
   * @since 1.0.0
   */
  public static byte[] reverse(byte[] value) {
    Validate.nullPointer(value);
    byte[] array = new byte[value.length];
    for (int i = 0; i < value.length; i++) {
      array[i] = value[value.length - i - 1];
    }
    return array;
  }

  /**
   * Reverse order.
   *
   * @param value value.
   * @return array in reverse order.
   * @since 1.0.0
   */
  public static char[] reverse(char[] value) {
    Validate.nullPointer(value);
    char[] array = new char[value.length];
    for (int i = 0; i < value.length; i++) {
      array[i] = value[value.length - i - 1];
    }
    return array;
  }

  /**
   * Reverse order.
   *
   * @param value value.
   * @return array in reverse order.
   * @since 1.0.0
   */
  public static short[] reverse(short[] value) {
    Validate.nullPointer(value);
    short[] array = new short[value.length];
    for (int i = 0; i < value.length; i++) {
      array[i] = value[value.length - i - 1];
    }
    return array;
  }

  /**
   * Reverse order.
   *
   * @param value value.
   * @return array in reverse order.
   * @since 1.0.0
   */
  public static int[] reverse(int[] value) {
    Validate.nullPointer(value);
    int[] array = new int[value.length];
    for (int i = 0; i < value.length; i++) {
      array[i] = value[value.length - i - 1];
    }
    return array;
  }

  /**
   * Reverse order.
   *
   * @param value value.
   * @return array in reverse order.
   * @since 1.0.0
   */
  public static float[] reverse(float[] value) {
    Validate.nullPointer(value);
    float[] array = new float[value.length];
    for (int i = 0; i < value.length; i++) {
      array[i] = value[value.length - i - 1];
    }
    return array;
  }

  /**
   * Reverse order.
   *
   * @param value value.
   * @return array in reverse order.
   * @since 1.0.0
   */
  public static long[] reverse(long[] value) {
    Validate.nullPointer(value);
    long[] array = new long[value.length];
    for (int i = 0; i < value.length; i++) {
      array[i] = value[value.length - i - 1];
    }
    return array;
  }

  /**
   * Reverse order.
   *
   * @param value value.
   * @return array in reverse order.
   * @since 1.0.0
   */
  public static double[] reverse(double[] value) {
    Validate.nullPointer(value);
    double[] array = new double[value.length];
    for (int i = 0; i < value.length; i++) {
      array[i] = value[value.length - i - 1];
    }
    return array;
  }

  /**
   * Reverse order.
   *
   * @param value value.
   * @param <T> type of value.
   * @return array in reverse order.
   * @since 1.0.0
   */
  @SuppressWarnings("unchecked")
  public static <T> T[] reverse(T[] value) {
    Validate.nullPointer(value);
    List<T> collections = java.util.Arrays.asList(value);
    Collections.reverse(collections);
    return (T[]) collections.toArray();
  }

  /**
   * Concatenate array.
   *
   * @param arrays arrays.
   * @return array.
   * @since 1.0.0
   */
  public static byte[] concatenate(byte[]... arrays) {
    Validate.nullPointer(arrays);
    int totalLen = 0;
    for (byte[] arr : arrays) {
      totalLen += arr.length;
    }
    byte[] all = new byte[totalLen];
    int copied = 0;
    for (byte[] arr : arrays) {
      System.arraycopy(arr, 0, all, copied, arr.length);
      copied += arr.length;
    }
    return all;
  }

  /**
   * Concatenate array.
   *
   * @param arrays arrays.
   * @return array.
   * @since 1.0.0
   */
  public static char[] concatenate(char[]... arrays) {
    Validate.nullPointer(arrays);
    int totalLen = 0;
    for (char[] arr : arrays) {
      totalLen += arr.length;
    }
    char[] all = new char[totalLen];
    int copied = 0;
    for (char[] arr : arrays) {
      System.arraycopy(arr, 0, all, copied, arr.length);
      copied += arr.length;
    }
    return all;
  }

  /**
   * Concatenate array.
   *
   * @param arrays arrays.
   * @return array.
   * @since 1.0.0
   */
  public static short[] concatenate(short[]... arrays) {
    Validate.nullPointer(arrays);
    int totalLen = 0;
    for (short[] arr : arrays) {
      totalLen += arr.length;
    }
    short[] all = new short[totalLen];
    int copied = 0;
    for (short[] arr : arrays) {
      System.arraycopy(arr, 0, all, copied, arr.length);
      copied += arr.length;
    }
    return all;
  }

  /**
   * Concatenate array.
   *
   * @param arrays arrays.
   * @return array.
   * @since 1.0.0
   */
  public static int[] concatenate(int[]... arrays) {
    Validate.nullPointer(arrays);
    int totalLen = 0;
    for (int[] arr : arrays) {
      totalLen += arr.length;
    }
    int[] all = new int[totalLen];
    int copied = 0;
    for (int[] arr : arrays) {
      System.arraycopy(arr, 0, all, copied, arr.length);
      copied += arr.length;
    }
    return all;
  }

  /**
   * Concatenate array.
   *
   * @param arrays arrays.
   * @return array.
   * @since 1.0.0
   */
  public static float[] concatenate(float[]... arrays) {
    Validate.nullPointer(arrays);
    int totalLen = 0;
    for (float[] arr : arrays) {
      totalLen += arr.length;
    }
    float[] all = new float[totalLen];
    int copied = 0;
    for (float[] arr : arrays) {
      System.arraycopy(arr, 0, all, copied, arr.length);
      copied += arr.length;
    }
    return all;
  }

  /**
   * Concatenate array.
   *
   * @param arrays arrays.
   * @return array.
   * @since 1.0.0
   */
  public static long[] concatenate(long[]... arrays) {
    Validate.nullPointer(arrays);
    int totalLen = 0;
    for (long[] arr : arrays) {
      totalLen += arr.length;
    }
    long[] all = new long[totalLen];
    int copied = 0;
    for (long[] arr : arrays) {
      System.arraycopy(arr, 0, all, copied, arr.length);
      copied += arr.length;
    }
    return all;
  }

  /**
   * Concatenate array.
   *
   * @param arrays arrays.
   * @return array.
   * @since 1.0.0
   */
  public static double[] concatenate(double[]... arrays) {
    Validate.nullPointer(arrays);
    int totalLen = 0;
    for (double[] arr : arrays) {
      totalLen += arr.length;
    }
    double[] all = new double[totalLen];
    int copied = 0;
    for (double[] arr : arrays) {
      System.arraycopy(arr, 0, all, copied, arr.length);
      copied += arr.length;
    }
    return all;
  }

  /**
   * Concatenate array.
   *
   * @param arrays arrays.
   * @param <T> type of array.
   * @return array.
   * @since 1.0.0
   */
  @SuppressWarnings("unchecked")
  public static <T> T[] concatenate(T[]... arrays) {
    Validate.nullPointer(arrays);
    int totalLen = 0;
    for (T[] arr : arrays) {
      totalLen += arr.length;
    }
    T[] all =
        (T[]) Array.newInstance(arrays.getClass().getComponentType().getComponentType(), totalLen);
    int copied = 0;
    for (T[] arr : arrays) {
      System.arraycopy(arr, 0, all, copied, arr.length);
      copied += arr.length;
    }
    return all;
  }

  /**
   * To string objects.
   *
   * <p>Use java.util.Array.toString(..) instead.
   *
   * @param objs objs.
   * @return returns {@link String}.
   */
  @Deprecated
  public static String toString(Object... objs) {
    return java.util.Arrays.toString(objs);
  }
}

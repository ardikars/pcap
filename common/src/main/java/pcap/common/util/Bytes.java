/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.common.util;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public final class Bytes {

  private Bytes() {}

  /**
   * Byte to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArray(final byte value) {
    return new byte[] {value};
  }

  /**
   * Short to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArray(final short value) {
    return new byte[] {(byte) (value >> 8 & 0xff), (byte) (value & 0xff)};
  }

  /**
   * Short array to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArray(final short[] value) {
    Validate.notInBounds(value, 0, value.length);
    byte[] array = new byte[value.length << 1];
    for (int i = 0; i < value.length; i++) {
      short x = value[i];
      int j = i << 1;
      array[j++] = (byte) ((x >> 8) & 0xff);
      array[j] = (byte) (x & 0xff);
    }
    return array;
  }

  public static byte[] toByteArray(final short[] value, final int offset, final int length) {
    Validate.notInBounds(value, offset, length);
    byte[] array = new byte[length << 1];
    int index = 0;
    for (int i = offset; i < offset + length; i++) {
      array[index++] = (byte) (value[i] >> 8 & 0xff);
      array[index++] = (byte) (value[i] & 0xff);
    }
    return array;
  }

  /**
   * Short to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArrayLE(final short value) {
    return new byte[] {(byte) (value & 0xff), (byte) (value >> 8 & 0xff)};
  }

  /**
   * Short array to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArrayLE(final short[] value) {
    Validate.notInBounds(value, 0, value.length);
    byte[] array = new byte[value.length << 1];
    for (int i = 0; i < value.length; i++) {
      short x = value[i];
      int j = i << 1;
      array[j++] = (byte) (x & 0xff);
      array[j] = (byte) ((x >> 8) & 0xff);
    }
    return array;
  }

  public static byte[] toByteArrayLE(final short[] value, final int offset, final int length) {
    Validate.notInBounds(value, offset, length);
    byte[] array = new byte[length << 1];
    int index = 0;
    for (int i = offset; i < offset + length; i++) {
      array[index++] = (byte) (value[i] & 0xff);
      array[index++] = (byte) (value[i] >> 8 & 0xff);
    }
    return array;
  }

  /**
   * Int to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArray(final int value) {
    return new byte[] {
      (byte) ((value >> 24) & 0xff),
      (byte) ((value >> 16) & 0xff),
      (byte) ((value >> 8) & 0xff),
      (byte) (value & 0xff)
    };
  }

  /**
   * Int array to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArray(final int[] value) {
    Validate.notInBounds(value, 0, value.length);
    byte[] array = new byte[value.length << 2];
    for (int i = 0; i < value.length; i++) {
      int x = value[i];
      int j = i << 2;
      array[j++] = (byte) ((x >> 24) & 0xff);
      array[j++] = (byte) ((x >> 16) & 0xff);
      array[j++] = (byte) ((x >> 8) & 0xff);
      array[j] = (byte) (x & 0xff);
    }
    return array;
  }

  public static byte[] toByteArray(final int[] value, final int offset, final int length) {
    Validate.notInBounds(value, offset, length);
    byte[] array = new byte[length << 2];
    int index = 0;
    for (int i = offset; i < offset + length; i++) {
      array[index++] = (byte) ((value[i] >> 24) & 0xff);
      array[index++] = (byte) ((value[i] >> 16) & 0xff);
      array[index++] = (byte) ((value[i] >> 8) & 0xff);
      array[index++] = (byte) (value[i] & 0xff);
    }
    return array;
  }

  /**
   * Int to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArrayLE(final int value) {
    return new byte[] {
      (byte) (value & 0xff),
      (byte) ((value >> 8) & 0xff),
      (byte) (value >> 16 & 0xff),
      (byte) (value >> 24 & 0xff)
    };
  }

  /**
   * Int array to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArrayLE(final int[] value) {
    Validate.notInBounds(value, 0, value.length);
    byte[] array = new byte[value.length << 2];
    for (int i = 0; i < value.length; i++) {
      int x = value[i];
      int j = i << 2;
      array[j++] = (byte) (x & 0xff);
      array[j++] = (byte) ((x >> 8) & 0xff);
      array[j++] = (byte) (x >> 16 & 0xff);
      array[j] = (byte) (x >> 24 & 0xff);
    }
    return array;
  }

  public static byte[] toByteArrayLE(final int[] value, final int offset, final int length) {
    Validate.notInBounds(value, offset, length);
    byte[] array = new byte[length << 2];
    int index = 0;
    for (int i = offset; i < offset + length; i++) {
      array[index++] = (byte) (value[i] & 0xff);
      array[index++] = (byte) ((value[i] >> 8) & 0xff);
      array[index++] = (byte) ((value[i] >> 16) & 0xff);
      array[index++] = (byte) ((value[i] >> 24) & 0xff);
    }
    return array;
  }

  /**
   * Long to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArray(final long value) {
    return new byte[] {
      (byte) ((value >> 56) & 0xff),
      (byte) ((value >> 48) & 0xff),
      (byte) ((value >> 40) & 0xff),
      (byte) ((value >> 32) & 0xff),
      (byte) ((value >> 24) & 0xff),
      (byte) ((value >> 16) & 0xff),
      (byte) ((value >> 8) & 0xff),
      (byte) (value & 0xff)
    };
  }

  /**
   * Long to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArrayLE(final long value) {
    return new byte[] {
      (byte) (value & 0xff),
      (byte) ((value >> 8) & 0xff),
      (byte) ((value >> 16) & 0xff),
      (byte) ((value >> 24) & 0xff),
      (byte) ((value >> 32) & 0xff),
      (byte) ((value >> 40) & 0xff),
      (byte) ((value >> 48) & 0xff),
      (byte) ((value >> 56) & 0xff)
    };
  }

  /**
   * Long array to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArray(final long[] value) {
    Validate.notInBounds(value, 0, value.length);
    byte[] array = new byte[value.length << 3];
    for (int i = 0; i < value.length; i++) {
      long x = value[i];
      int j = i << 3;
      array[j++] = (byte) ((x >> 56) & 0xff);
      array[j++] = (byte) ((x >> 48) & 0xff);
      array[j++] = (byte) ((x >> 40) & 0xff);
      array[j++] = (byte) ((x >> 32) & 0xff);
      array[j++] = (byte) ((x >> 24) & 0xff);
      array[j++] = (byte) ((x >> 16) & 0xff);
      array[j++] = (byte) ((x >> 8) & 0xff);
      array[j] = (byte) (x & 0xff);
    }
    return array;
  }

  public static byte[] toByteArray(final long[] value, final int offset, final int length) {
    Validate.notInBounds(value, offset, length);
    byte[] array = new byte[length << 3];
    int index = 0;
    for (int i = offset; i < offset + length; i++) {
      array[index++] = (byte) ((value[i] >> 56) & 0xff);
      array[index++] = (byte) ((value[i] >> 48) & 0xff);
      array[index++] = (byte) ((value[i] >> 40) & 0xff);
      array[index++] = (byte) ((value[i] >> 32) & 0xff);
      array[index++] = (byte) ((value[i] >> 24) & 0xff);
      array[index++] = (byte) ((value[i] >> 16) & 0xff);
      array[index++] = (byte) ((value[i] >> 8) & 0xff);
      array[index++] = (byte) (value[i] & 0xff);
    }
    return array;
  }

  public static byte[] toByteArrayLE(final long[] value, final int offset, final int length) {
    Validate.notInBounds(value, offset, length);
    byte[] array = new byte[length << 3];
    int index = 0;
    for (int i = offset; i < offset + length; i++) {
      array[index++] = (byte) (value[i] & 0xff);
      array[index++] = (byte) ((value[i] >> 8) & 0xff);
      array[index++] = (byte) ((value[i] >> 16) & 0xff);
      array[index++] = (byte) ((value[i] >> 24) & 0xff);
      array[index++] = (byte) ((value[i] >> 32) & 0xff);
      array[index++] = (byte) ((value[i] >> 40) & 0xff);
      array[index++] = (byte) ((value[i] >> 48) & 0xff);
      array[index++] = (byte) ((value[i] >> 56) & 0xff);
    }
    return array;
  }

  /**
   * Long array to byte array.
   *
   * @param value value.
   * @return byte array.
   * @since 1.0.0
   */
  public static byte[] toByteArrayLE(final long[] value) {
    Validate.notInBounds(value, 0, value.length);
    byte[] array = new byte[value.length << 3];
    for (int i = 0; i < value.length; i++) {
      long x = value[i];
      int j = i << 3;
      array[j++] = (byte) (x & 0xff);
      array[j++] = (byte) ((x >> 8) & 0xff);
      array[j++] = (byte) ((x >> 16) & 0xff);
      array[j++] = (byte) ((x >> 24) & 0xff);
      array[j++] = (byte) ((x >> 32) & 0xff);
      array[j++] = (byte) ((x >> 40) & 0xff);
      array[j++] = (byte) ((x >> 48) & 0xff);
      array[j] = (byte) ((x >> 56) & 0xff);
    }
    return array;
  }
}

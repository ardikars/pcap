/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

/**
 * Integer utils.
 *
 * @since 1.0.0
 */
public final class Integers {

  private Integers() {
    //
  }

  /**
   * Byte array to int.
   *
   * @param values byte array.
   * @return int representation.
   * @since 1.0.0
   */
  public static int toInteger(byte[] values) {
    Validate.notInBounds(values.length, 0, 4);
    return ((values[0] & 0xFF) << 24)
        | ((values[1] & 0xFF) << 16)
        | ((values[2] & 0xFF) << 8)
        | (values[3] & 0xFF);
  }

  /**
   * Byte array to int (little endian).
   *
   * @param values byte array.
   * @return int representation.
   * @since 1.0.0
   */
  public static int toIntegerLE(byte[] values) {
    Validate.notInBounds(values.length, 0, 4);
    return (values[0] & 0xFF)
        | ((values[1] & 0xFF) << 8)
        | ((values[2] & 0xFF) << 16)
        | ((values[3] & 0xFF) << 24);
  }

  /**
   * Byte array to int.
   *
   * @param values byte array.
   * @param offset offset.
   * @return int representation.
   * @since 1.0.0
   */
  public static int toInteger(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 4);
    return ((values[offset] & 0xFF) << 24)
        | ((values[offset + 1] & 0xFF) << 16)
        | ((values[offset + 2] & 0xFF) << 8)
        | (values[offset + 3] & 0xFF);
  }

  /**
   * Byte array to int (little endian).
   *
   * @param values byte array.
   * @param offset offset.
   * @return int representation.
   * @since 1.0.0
   */
  public static int toIntegerLE(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 4);
    return (values[offset] & 0xFF)
        | ((values[offset + 1] & 0xFF) << 8)
        | ((values[offset + 2] & 0xFF) << 16)
        | ((values[offset + 3] & 0xFF) << 24);
  }
}

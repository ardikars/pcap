/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.common.util;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public final class Shorts {

  private Shorts() {
    //
  }

  public static short toShort(byte[] values) {
    Validate.notInBounds(values.length, 0, 2);
    return (short) ((values[0] & 0xFF) << 8 | values[1] & 0xFF);
  }

  public static short toShort(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 2);
    return (short) ((values[offset] & 0xFF) << 8 | values[offset + 1] & 0xFF);
  }

  public static short toShortLE(byte[] values) {
    Validate.notInBounds(values.length, 0, 2);
    return (short) (values[0] & 0xFF | (values[1] & 0xFF) << 8);
  }

  public static short toShortLE(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 2);
    return (short) (values[offset] & 0xFF | (values[offset + 1] & 0xFF) << 8);
  }
}

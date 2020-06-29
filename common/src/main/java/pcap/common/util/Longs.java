/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.nio.ByteOrder;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public final class Longs {

  private Longs() {
    //
  }

  public static long toLong(byte[] values) {
    return toLong(values, 0, ByteOrder.BIG_ENDIAN);
  }

  public static long toLong(byte[] values, int offset, ByteOrder byteOrder) {
    Validate.notInBounds(values.length, offset, 8);
    if (byteOrder.equals(ByteOrder.BIG_ENDIAN)) {
      return (((values[offset] & 0xFFL) << 56)
          | ((values[offset + 1] & 0xFFL) << 48)
          | ((values[offset + 2] & 0xFFL) << 40)
          | ((values[offset + 3] & 0xFFL) << 32)
          | ((values[offset + 4] & 0xFFL) << 24)
          | ((values[offset + 5] & 0xFFL) << 16)
          | ((values[offset + 6] & 0xFFL) << 8)
          | (values[offset + 7] & 0xFFL));
    } else {
      return (values[offset] & 0xFFL)
          | ((values[offset + 1] & 0xFFL) << 8)
          | ((values[offset + 2] & 0xFFL) << 16)
          | ((values[offset + 3] & 0xFFL) << 24)
          | ((values[offset + 4] & 0xFFL) << 32)
          | ((values[offset + 5] & 0xFFL) << 40)
          | ((values[offset + 6] & 0xFFL) << 48)
          | ((values[offset + 7] & 0xFFL) << 56);
    }
  }
}

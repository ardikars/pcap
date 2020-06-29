/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.nio.ByteOrder;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public final class Integers {

  private Integers() {
    //
  }

  public static int toInteger(byte[] values) {
    return toInteger(values, 0, ByteOrder.BIG_ENDIAN);
  }

  public static int toInteger(byte[] values, int offset, ByteOrder byteOrder) {
    Validate.notInBounds(values.length, offset, 4);
    if (byteOrder.equals(ByteOrder.BIG_ENDIAN)) {
      return ((values[offset] & 0xFF) << 24)
          | ((values[offset + 1] & 0xFF) << 16)
          | ((values[offset + 2] & 0xFF) << 8)
          | (values[offset + 3] & 0xFF);
    } else {
      return (values[offset] & 0xFF)
          | ((values[offset + 1] & 0xFF) << 8)
          | ((values[offset + 2] & 0xFF) << 16)
          | ((values[offset + 3] & 0xFF) << 24);
    }
  }
}

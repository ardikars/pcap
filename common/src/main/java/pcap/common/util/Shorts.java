/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.nio.ByteOrder;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public class Shorts {

  public static short toShort(byte[] values) {
    return toShort(values, 0, ByteOrder.BIG_ENDIAN);
  }

  public static short toShort(byte[] values, int offset, ByteOrder byteOrder) {
    Validate.notInBounds(values.length, offset, 2);
    if (byteOrder.equals(ByteOrder.BIG_ENDIAN)) {
      return (short) ((values[offset] & 0xFF) << 8 | values[offset + 1] & 0xFF);
    } else {
      return (short) (values[offset] & 0xFF | (values[offset + 1] & 0xFF << 8));
    }
  }
}

/** This code is licenced under the GPL version 2. */
package pcap.common.util;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public final class Integers {

  private Integers() {
    //
  }

  public static int toInteger(byte[] values) {
    Validate.notInBounds(values.length, 0, 4);
    return ((values[0] & 0xFF) << 24)
        | ((values[1] & 0xFF) << 16)
        | ((values[2] & 0xFF) << 8)
        | (values[3] & 0xFF);
  }

  public static int toIntegerLE(byte[] values) {
    Validate.notInBounds(values.length, 0, 4);
    return (values[0] & 0xFF)
        | ((values[1] & 0xFF) << 8)
        | ((values[2] & 0xFF) << 16)
        | ((values[3] & 0xFF) << 24);
  }

  public static int toInteger(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 4);
    return ((values[offset] & 0xFF) << 24)
        | ((values[offset + 1] & 0xFF) << 16)
        | ((values[offset + 2] & 0xFF) << 8)
        | (values[offset + 3] & 0xFF);
  }

  public static int toIntegerLE(byte[] values, int offset) {
    Validate.notInBounds(values.length, offset, 4);
    return (values[offset] & 0xFF)
        | ((values[offset + 1] & 0xFF) << 8)
        | ((values[offset + 2] & 0xFF) << 16)
        | ((values[offset + 3] & 0xFF) << 24);
  }
}

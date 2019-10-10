/** This code is licenced under the GPL version 2. */
package pcap.common.memory.accessor;

import java.nio.ByteOrder;
import pcap.common.annotation.Inclubating;
import pcap.common.internal.UnsafeHelper;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class ByteAccessors {

  private static final boolean UNALIGN = UnsafeHelper.isUnaligned();

  public static final boolean BIG_ENDIAN_NATIVE_ORDER =
      ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN;

  public static ByteAccessor byteAccessor() {
    return byteAccessor(UNALIGN, BIG_ENDIAN_NATIVE_ORDER);
  }

  /**
   * Get {@link ByteAccessor} instance with given aligness and endianess.
   *
   * @param unaligned unaligned memory.
   * @param bigEndianess endianess.
   * @return returns {@link ByteAccessor} instance.
   */
  public static ByteAccessor byteAccessor(boolean unaligned, boolean bigEndianess) {
    ByteAccessor byteAccessor;
    if (unaligned) {
      if (bigEndianess) {
        byteAccessor = new UnalignBEByteAccessor();
      } else {
        byteAccessor = new UnalignLEByteAccessor();
      }
    } else {
      byteAccessor = new AlignByteAccessor();
    }
    return byteAccessor;
  }
}

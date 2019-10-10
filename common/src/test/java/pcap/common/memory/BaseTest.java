/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.security.SecureRandom;
import java.util.Random;
import pcap.common.internal.Unsafe;

abstract class BaseTest {

  Random RANDOM = new SecureRandom();

  int BIT_SIZE = 2;
  int BYTE_SIZE = Byte.SIZE / Byte.SIZE;
  int SHORT_SIZE = Short.SIZE / Byte.SIZE;
  int INT_SIZE = Integer.SIZE / Byte.SIZE;
  int LONG_SIZE = Long.SIZE / Byte.SIZE;

  int DEFAULT_CAPACITY =
      16; // LONG_SIZE * RANDOM.nextInt(Integer.MAX_VALUE / (BIT_SIZE * INT_SIZE));
  int DEFAULT_MAX_CAPACITY = DEFAULT_CAPACITY + INT_SIZE;

  byte[] DUMMY = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

  boolean hasUnsafe = Unsafe.HAS_UNSAFE;

  static {
    System.setProperty("pcap.unsafe", "true");
  }
}

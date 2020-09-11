/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.security.SecureRandom;
import java.util.Random;

public abstract class BaseTest {

  protected Random RANDOM = new SecureRandom();

  protected int BIT_SIZE = 2;
  protected int BYTE_SIZE = Byte.SIZE / Byte.SIZE;
  protected int SHORT_SIZE = Short.SIZE / Byte.SIZE;
  protected int INT_SIZE = Integer.SIZE / Byte.SIZE;
  protected int LONG_SIZE = Long.SIZE / Byte.SIZE;

  protected int DEFAULT_CAPACITY =
      16; // LONG_SIZE * RANDOM.nextInt(Integer.MAX_VALUE / (BIT_SIZE * INT_SIZE));
  protected int DEFAULT_MAX_CAPACITY = DEFAULT_CAPACITY + INT_SIZE;

  protected byte[] DUMMY = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
}

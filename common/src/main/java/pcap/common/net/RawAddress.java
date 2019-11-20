/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import pcap.common.annotation.Inclubating;

/**
 * Default implementation of raw byte array address.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Inclubating
public class RawAddress implements Address {

  private final byte[] address;

  private RawAddress(byte[] address) {
    this.address = address;
  }

  /**
   * Create instance of {@link RawAddress}.
   *
   * @param bytes byte array.
   * @return returns {@link RawAddress}/
   */
  public static RawAddress valueOf(byte[] bytes) {
    return new RawAddress(bytes);
  }

  @Override
  public byte[] address() {
    byte[] data = new byte[address.length];
    System.arraycopy(address, 0, data, 0, data.length);
    return data;
  }
}

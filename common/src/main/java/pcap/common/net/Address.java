/** This code is licenced under the GPL version 2. */
package pcap.common.net;

/**
 * Used to wrap raw byte array address.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface Address {

  /**
   * Get raw byte array address.
   *
   * @return returns byte array.
   */
  byte[] address();
}

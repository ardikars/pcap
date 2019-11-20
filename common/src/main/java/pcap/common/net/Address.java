/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import pcap.common.annotation.Inclubating;

/**
 * Used to wrap raw byte array address.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Inclubating
public interface Address {

  /**
   * Get raw byte array address.
   *
   * @return returns byte array.
   */
  byte[] address();
}

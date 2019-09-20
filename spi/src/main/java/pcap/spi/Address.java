/** This code is licenced under the GPL version 2. */
package pcap.spi;

import java.net.InetAddress;

/**
 * Representation of an interface address.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Address extends Iterable<Address> {

  /**
   * Next available address.
   *
   * @return returns next address if available, {@code null} otherwise.
   */
  Address next();

  /**
   * Interface address.
   *
   * @return returns interface address.
   */
  InetAddress address();

  /**
   * Netmask for interface address ({@link #address()}).
   *
   * @return returns netmask for ({@link #address()}).
   */
  InetAddress netmask();

  /**
   * Brodcast address for interface address ({@link #address()}).
   *
   * @return returns brodcast address for ({@link #address()}).
   */
  InetAddress broadcast();

  /**
   * P2P destination address for interface address ({@link #address()}).
   *
   * @return returns P2P destination address for ({@link #address()}).
   */
  InetAddress destination();
}

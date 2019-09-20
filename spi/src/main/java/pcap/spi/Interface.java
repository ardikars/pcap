/** This code is licenced under the GPL version 2. */
package pcap.spi;

/**
 * Item in a list of interfaces.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Interface extends Iterable<Interface> {

  /**
   * Next available interface.
   *
   * @return returns next interface if available, {@code null} otherwise.
   */
  Interface next();

  /**
   * Name to hand to {@code "pcap_open_live()"}.
   *
   * @return returns interface name.
   */
  String name();

  /**
   * Textual description of interface, or {@code null}.
   *
   * @return returns interface description.
   */
  String description();

  /**
   * Interface addresses.
   *
   * @return returns interface addresses.
   */
  Address addresses();

  /**
   * Interface flags.
   *
   * @return returns interface flags.
   */
  int flags();
}

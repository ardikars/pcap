/** This code is licenced under the GPL version 2. */
package pcap.spi;

/**
 * Item in a list of interfaces.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface Interface extends Iterable<Interface> {

  /**
   * Next available interface.
   *
   * @return returns next interface if available, {@code null} otherwise.
   * @since 1.0.0
   */
  Interface next();

  /**
   * Name to hand to {@code "pcap_open_live()"}.
   *
   * @return returns interface name.
   * @since 1.0.0
   */
  String name();

  /**
   * Textual description of interface, or {@code null}.
   *
   * @return returns interface description.
   * @since 1.0.0
   */
  String description();

  /**
   * Interface addresses.
   *
   * @return returns interface addresses.
   * @since 1.0.0
   */
  Address addresses();

  /**
   * Interface flags.
   *
   * @return returns interface flags.
   * @since 1.0.0
   */
  int flags();
}

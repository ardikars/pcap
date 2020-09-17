/** This code is licenced under the GPL version 2. */
package pcap.spi;

/**
 * As returned by the pcap_stats().
 *
 * <p>Deprecated: Use {@link Statistics} instead.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Deprecated
public interface Status {

  /**
   * Number of packets received.
   *
   * @return returns number of packets received.
   * @since 1.0.0
   */
  int received();

  /**
   * Number of packets dropped.
   *
   * @return returns number of packets dropped.
   * @since 1.0.0
   */
  int dropped();

  /**
   * Number of packets dropped by interface (only supported on some platforms).
   *
   * @return returns number of packets dropped by interface.
   * @since 1.0.0
   */
  int droppedByInterface();
}

/** This code is licenced under the GPL version 2. */
package pcap.spi;

/**
 * As returned by the pcap_stats().
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Status {

  /**
   * Number of packets received.
   *
   * @return returns number of packets received.
   */
  int received();

  /**
   * Number of packets dropped.
   *
   * @return returns number of packets dropped.
   */
  int dropped();

  /**
   * Number of packets dropped by interface (only supported on some platforms).
   *
   * @return returns number of packets dropped by interface.
   */
  int droppedByInterface();
}

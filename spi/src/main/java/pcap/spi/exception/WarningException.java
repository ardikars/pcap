/** This code is licenced under the GPL version 2. */
package pcap.spi.exception;

/**
 * Warning codes for the pcap API. These will all be positive and non-zero, so they won't look like
 * errors.
 *
 * <p>Generic warning code ({@code 1}).
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public class WarningException extends RuntimeException {

  // #define PCAP_WARNING                     1 /* generic warning code */
  // #define PCAP_WARNING_PROMISC_NOTSUP      2 /* this device doesn't support promiscuous mode */
  // #define PCAP_WARNING_TSTAMP_TYPE_NOTSUP  3 /* the requested time stamp type is not supported
  // */

  public WarningException(String message) {
    super(message);
  }
}

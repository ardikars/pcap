package pcap.spi.exception;

/**
 * Timeout occurred while reading packet's.
 *
 * @since 1.0.0
 */
public class TimeoutException extends Exception {

  public TimeoutException(String message) {
    super(message);
  }
}

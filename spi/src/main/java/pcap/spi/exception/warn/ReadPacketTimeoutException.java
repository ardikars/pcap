package pcap.spi.exception.warn;

public class ReadPacketTimeoutException extends RuntimeException {

  public ReadPacketTimeoutException(String message) {
    super(message);
  }
}

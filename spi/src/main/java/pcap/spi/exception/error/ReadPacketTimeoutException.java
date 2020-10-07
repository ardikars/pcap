package pcap.spi.exception.error;

import pcap.spi.exception.ErrorException;

public class ReadPacketTimeoutException extends ErrorException {

  public ReadPacketTimeoutException(String message) {
    super(message);
  }
}

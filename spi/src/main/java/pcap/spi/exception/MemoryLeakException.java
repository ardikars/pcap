package pcap.spi.exception;

import pcap.spi.annotation.Incubating;

@Incubating
public class MemoryLeakException extends RuntimeException {

  public MemoryLeakException(String message) {
    super(message);
  }
}

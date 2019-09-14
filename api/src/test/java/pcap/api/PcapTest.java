package pcap.api;

import org.junit.jupiter.api.Test;
import pcap.api.internal.PcapInterface;
import pcap.api.internal.exception.PcapErrorException;

public class PcapTest {

  @Test
  public void lookup() throws PcapErrorException {
    PcapInterface.lookup().forEach(System.out::println);
  }
}

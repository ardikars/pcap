package pcap.api;

import java.util.Iterator;
import pcap.spi.Interface;
import pcap.spi.Service;
import pcap.spi.exception.ErrorException;

public abstract class BaseTest {

  protected static final int MAX_PKT = 1;
  protected static final String SAMPLE_NANOSECOND_PCAP =
      "src/test/resources/sample_nanosecond.pcap";
  protected static final String SAMPLE_MICROSECOND_PCAP =
      "src/test/resources/sample_microsecond.pcap";
  protected static final int SAMPLE_PCAP_SNAPLEN = 262144;
  protected static final String SAMPLE_PCAPNG = "src/test/resources/sample.pcapng";

  public Interface loopbackInterface(Service service) throws ErrorException {
    Iterator<Interface> iterator = service.lookupInterfaces().iterator();
    if (iterator != null) {
      while (iterator.hasNext()) {
        Interface source = iterator.next();
        if ((source.flags() & 0x00000001) != 0) {
          return source;
        }
      }
    }
    throw new ErrorException("Loopback interface is not found.");
  }
}

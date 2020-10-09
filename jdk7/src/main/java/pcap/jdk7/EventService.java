package pcap.jdk7;

import pcap.spi.Pcap;
import pcap.spi.annotation.Incubating;

@Incubating
public interface EventService extends AutoCloseable {

  @Incubating
  EventService open(Pcap pcap);

  @Incubating
  int events(int timeout);
}

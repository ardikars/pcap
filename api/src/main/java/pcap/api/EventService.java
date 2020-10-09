package pcap.api;

import pcap.spi.Pcap;
import pcap.spi.annotation.Incubating;

@Incubating
public interface EventService extends AutoCloseable {

  @Incubating
  EventService open(Pcap pcap);

  @Incubating
  <A> void events(int timeout, Event<A> event, A attachment);
}

package pcap.api;

import java.nio.channels.SelectionKey;
import pcap.spi.Pcap;
import pcap.spi.annotation.Incubating;

@Incubating
public interface Event<A> {

  int OP_ERROR = -1;
  int OP_TIMEOUT = 0;
  int OP_READ = SelectionKey.OP_READ;

  @Incubating
  void signal(A attachment, Pcap pcap, int opts);
}

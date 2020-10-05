package pcap.spi.option;

import java.util.concurrent.TimeUnit;
import pcap.spi.Pcap;

public class DefaultEventOptions implements Pcap.Event.Options {

  private int timeout; // in millisecond

  public DefaultEventOptions() {
    this.timeout = -1;
  }

  public int timeout() {
    return timeout;
  }

  public DefaultEventOptions timeout(int timeout, TimeUnit unit) {
    this.timeout = (int) unit.toMillis(timeout) & Integer.MAX_VALUE;
    return this;
  }
}

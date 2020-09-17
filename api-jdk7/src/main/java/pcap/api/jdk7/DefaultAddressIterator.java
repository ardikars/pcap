package pcap.api.jdk7;

import java.util.Iterator;
import java.util.NoSuchElementException;
import pcap.spi.Address;

public class DefaultAddressIterator implements Iterator<Address> {

  private DefaultAddress next;

  public DefaultAddressIterator(DefaultAddress next) {
    this.next = next;
  }

  @Override
  public boolean hasNext() {
    return next != null;
  }

  @Override
  public DefaultAddress next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }
    DefaultAddress previous = next;
    next = next.next();
    return previous;
  }
}

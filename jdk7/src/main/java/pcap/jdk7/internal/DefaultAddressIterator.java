package pcap.jdk7.internal;

import java.util.Iterator;
import java.util.NoSuchElementException;
import pcap.spi.Address;

class DefaultAddressIterator implements Iterator<Address> {

  private DefaultAddress next;

  DefaultAddressIterator(DefaultAddress next) {
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

  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }
}

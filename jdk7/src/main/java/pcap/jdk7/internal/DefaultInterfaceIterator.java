package pcap.jdk7.internal;

import java.util.Iterator;
import java.util.NoSuchElementException;
import pcap.spi.Interface;

class DefaultInterfaceIterator implements Iterator<Interface> {

  private Interface next;

  DefaultInterfaceIterator(Interface next) {
    this.next = next;
  }

  @Override
  public boolean hasNext() {
    return next != null;
  }

  @Override
  public Interface next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }
    Interface previous = next;
    next = next.next();
    return previous;
  }

  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }
}

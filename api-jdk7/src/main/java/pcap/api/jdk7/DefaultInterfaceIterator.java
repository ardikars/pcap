package pcap.api.jdk7;

import java.util.Iterator;
import java.util.NoSuchElementException;
import pcap.spi.Interface;

public class DefaultInterfaceIterator implements Iterator<Interface> {

  private DefaultInterface next;

  public DefaultInterfaceIterator(DefaultInterface next) {
    this.next = next;
  }

  @Override
  public boolean hasNext() {
    return next != null;
  }

  @Override
  public DefaultInterface next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }
    DefaultInterface previous = next;
    next = next.next();
    return previous;
  }
}

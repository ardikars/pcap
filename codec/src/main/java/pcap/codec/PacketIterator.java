/** This code is licenced under the GPL version 2. */
package pcap.codec;

import java.util.Iterator;
import java.util.NoSuchElementException;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class PacketIterator implements Iterator<Packet> {

  private Packet next;

  public PacketIterator(final Packet packet) {
    this.next = packet;
  }

  @Override
  public boolean hasNext() {
    return next != null;
  }

  @Override
  public Packet next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }
    Packet previous = next;
    next = next.payload();
    return previous;
  }

  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }
}

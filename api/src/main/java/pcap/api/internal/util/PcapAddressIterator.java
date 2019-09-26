/** This code is licenced under the GPL version 2. */
package pcap.api.internal.util;

import java.util.Iterator;
import java.util.NoSuchElementException;
import pcap.common.annotation.Inclubating;
import pcap.spi.Address;

/**
 * {@link Address} iterator.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapAddressIterator implements Iterator<Address> {

  private Address next;

  public PcapAddressIterator(final Address pcapAddress) {
    this.next = pcapAddress;
  }

  @Override
  public boolean hasNext() {
    return next != null;
  }

  @Override
  public Address next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }
    Address previous = next;
    next = next.next();
    return previous;
  }
}

/**
 * This code is licenced under the GPL version 2.
 */
package pcap.api.internal.util;

import pcap.spi.Address;

import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
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

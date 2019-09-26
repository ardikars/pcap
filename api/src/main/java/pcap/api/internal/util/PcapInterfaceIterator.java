/** This code is licenced under the GPL version 2. */
package pcap.api.internal.util;

import java.util.Iterator;
import java.util.NoSuchElementException;
import pcap.common.annotation.Inclubating;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Interface;

/**
 * {@link Interface} iterator.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapInterfaceIterator implements Iterator<Interface> {

  private static final Logger LOGGER = LoggerFactory.getLogger(Interface.class);

  private Interface next;

  public PcapInterfaceIterator(final Interface pcapInterface) {
    this.next = pcapInterface;
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
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug(next.toString());
    }
    Interface previous = next;
    next = next.next();
    return previous;
  }
}

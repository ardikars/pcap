/**
 * This code is licenced under the GPL version 2.
 */
package pcap.spi;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Interface extends Iterable<Interface> {

    Interface next();

    String name();

    String description();

    Address addresses();

    int flags();

}

/**
 * This code is licenced under the GPL version 2.
 */
package pcap.spi;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface PacketHeader {

    Timestamp timestamp();

    int captureLength();

    int length();

}

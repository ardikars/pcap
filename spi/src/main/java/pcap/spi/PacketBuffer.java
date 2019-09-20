/** This code is licenced under the GPL version 2. */
package pcap.spi;

import java.nio.ByteBuffer;

/**
 * A {@link ByteBuffer} wrapper.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface PacketBuffer {

  ByteBuffer buffer();
}

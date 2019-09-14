/** This code is licenced under the GPL version 2. */
package pcap.codec;

import java.io.Serializable;
import java.util.List;
import pcap.common.annotation.Inclubating;
import pcap.common.util.NamedNumber;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public interface Packet extends Iterable<Packet>, Serializable {

  /**
   * Returns the {@link Header} object representing this packet's header.
   *
   * @return returns null if header doesn't exist, {@link Header} object otherwise.
   */
  Header getHeader();

  /**
   * Returns the {@link Packet} object representing this packet's payload.
   *
   * @return returns null if a payload doesn't exits, {@link Packet} object otherwise.
   */
  Packet getPayload();

  /**
   * Ensures that given packet type is included on this {@link Packet} object.
   *
   * @param clazz packet type.
   * @param <T> type.
   * @return returns true if this packet is or its payload includes an object of specified packet
   *     class; false otherwise.
   */
  <T extends Packet> boolean contains(Class<T> clazz);

  /**
   * Returns list of specify packet's.
   *
   * @param clazz packet type.
   * @param <T> type.
   * @return returns list of {@link Packet} object.
   */
  <T extends Packet> List<T> get(Class<T> clazz);

  /** This interface representing a packet header. */
  interface Header extends Serializable {

    /**
     * Returns the payload type.
     *
     * @param <T> type.
     * @return returns payload type.
     */
    <T extends NamedNumber> T getPayloadType();

    /**
     * Returns header length.
     *
     * @return returns header length.
     */
    int getLength();
  }
}

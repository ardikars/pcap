/** This code is licenced under the GPL version 2. */
package pcap.spi;

/**
 * A callback function used to handle {@link Pcap#loop(int, PacketHandler, Object)} and {@link
 * Pcap#dispatch(int, PacketHandler, Object)}.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface PacketHandler<T> {

  /**
   * On received.
   *
   * @param args attachments.
   * @param header header.
   * @param buffer buffer.
   * @since 1.0.0
   */
  void gotPacket(T args, PacketHeader header, PacketBuffer buffer);
}

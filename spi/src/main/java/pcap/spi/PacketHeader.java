/** This code is licenced under the GPL version 2. */
package pcap.spi;

/**
 * Generic per-packet information, as supplied by libpcap.
 *
 * <p>The time stamp can and should be a {@link Timestamp}, regardless of whether your system
 * supports 32-bit {@link Timestamp#second()} in {@link Timestamp}, 64-bit {@link
 * Timestamp#second()} in {@link Timestamp}, or both if it supports both 32-bit and 64-bit
 * applications. The on-disk format of savefiles uses 32-bit {@link Timestamp#second()} (and {@link
 * Timestamp#microSecond()} ()}); this structure is irrelevant to that. 32-bit and 64-bit versions
 * of libpcap, even if they're on the same platform, should supply the appropriate version of {@link
 * Timestamp}, even if that's not what the underlying packet capture mechanism supplies.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface PacketHeader {

  /**
   * Timestamp per-packet.
   *
   * @return returns timestamp.
   * @since 1.0.0
   */
  Timestamp timestamp();

  /**
   * Length of portion present (must be less then or equal to {@link PacketHeader#length()}).
   *
   * @return returns length of portion present.
   * @since 1.0.0
   */
  int captureLength();

  /**
   * Length this packet (off wire).
   *
   * @return returns length this packet (off wire).
   * @since 1.0.0
   */
  int length();
}

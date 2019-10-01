package pcap.spi;

import java.nio.ByteBuffer;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;

/**
 * A handle for {@code pcap} api.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Pcap extends AutoCloseable {

  /**
   * Open {@link Dumper} handler.
   *
   * @param file location of capture file will saved.
   * @return returns {@code Pcap} {@link Dumper} handle.
   * @throws ErrorException generic exception.
   */
  Dumper dumpOpen(String file) throws ErrorException;

  /**
   * Append packet buffer on existing {@code pcap} file.
   *
   * @param file location of saved file.
   * @return returns {@code Pcap} {@link Dumper} handle.
   * @throws ErrorException generic error.
   */
  Dumper dumpOpenAppend(String file) throws ErrorException;

  /**
   * BPF packet filter.
   *
   * @param filter filter expression.
   * @param optimize {@code true} for optimized filter, {@code false} otherwise.
   * @throws ErrorException generic error.
   */
  void setFilter(String filter, boolean optimize) throws ErrorException;

  /**
   * Process packets from a live {@code PcapLive} or {@code PcapOffline}.
   *
   * @param count maximum number of packets to process before returning. A value of -1 or 0 for
   *     count is equivalent to infinity, so that packets are processed until another ending
   *     condition occurs.
   * @param handler {@link PacketHandler} callback function.
   * @param args user args.
   * @param <T> args type.
   * @throws BreakException {@link Pcap#breakLoop()} is called.
   * @throws ErrorException Generic error.
   */
  <T> void loop(int count, PacketHandler<T> handler, T args) throws BreakException, ErrorException;

  /**
   * Represent packet statistics from the start of the run to the time of the call.
   *
   * <p>Supported only on live captures, not on {@code PcapOffline}; no statistics are stored in
   * {@code PcapOffline} so no statistics are available when reading from a {@code PcapOffline}
   *
   * @return returns {@link Status} on success.
   * @throws ErrorException There is an error or if this {@link Pcap} doesn't support packet
   *     statistics.
   */
  Status status() throws ErrorException;

  /**
   * Force a {@link Pcap#loop(int, PacketHandler, Object)} call to return And throw {@link
   * BreakException} on {@link Pcap#loop(int, PacketHandler, Object)}.
   */
  void breakLoop();

  /**
   * Sends a raw packet through the network interface.
   *
   * @param directBuffer the data of the packet, including the link-layer header.
   * @param size the number of bytes in the packet.
   * @throws ErrorException generic error.
   */
  void send(ByteBuffer directBuffer, int size) throws ErrorException;

  /**
   * Close {@code PcapLive} or {@code PcapOffline}. <br>
   * Note: BPF handle will closed automaticly.
   */
  @Override
  void close();
}

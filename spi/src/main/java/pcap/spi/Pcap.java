package pcap.spi;

import java.nio.ByteBuffer;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;

/**
 * A handle for {@code pcap} api.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface Pcap extends AutoCloseable {

  /**
   * Open {@link Dumper} handler.
   *
   * @param file location of capture file will saved.
   * @return returns {@code Pcap} {@link Dumper} handle.
   * @throws ErrorException generic exception.
   * @since 1.0.0
   */
  Dumper dumpOpen(String file) throws ErrorException;

  /**
   * Append packet buffer on existing {@code pcap} file.
   *
   * @param file location of saved file.
   * @return returns {@code Pcap} {@link Dumper} handle.
   * @throws ErrorException generic error.
   * @since 1.0.0
   */
  Dumper dumpOpenAppend(String file) throws ErrorException;

  /**
   * BPF packet filter.
   *
   * @param filter filter expression.
   * @param optimize {@code true} for optimized filter, {@code false} otherwise.
   * @throws ErrorException generic error.
   * @since 1.0.0
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
   * @since 1.0.0
   */
  <T> void loop(int count, PacketHandler<T> handler, T args) throws BreakException, ErrorException;

  /**
   * processes packets from a live capture or {@code PcapLive} until cnt packets are processed,
   * the end of the current bufferful of packets is reached when doing a live capture,
   * the end of the {@code 'savefile'} is reached when reading from a {@code 'savefile'},
   * {@code Pcap#breakLoop()} is called, or an error occurs. Thus, when doing a live capture,
   * cnt is the maximum number of packets to process before returning, but is not a minimum number;
   * when reading a live capture, only one bufferful of packets is read at a time,
   * so fewer than cnt packets may be processed. A value of -1 or 0 for cnt causes all the packets
   * received in one buffer to be processed when reading a live capture, and causes all the packets
   * in the file to be processed when reading a {@code 'savefile'}.
   *
   * (In older versions of libpcap, the behavior when cnt was 0 was undefined;
   * different platforms and devices behaved differently, so code that must work with
   * older versions of libpcap should use -1, nor 0, as the value of cnt.)
   *
   * callback specifies a {@code PacketHandler} routine to be called with three arguments
   * : a {@code args} which is passed in the user argument to {@code Pcap#loop()} or {@code Pcap#dispatch()},
   * a const struct pcap_pkthdr pointer pointing to the packet time stamp and lengths,
   * and a {@code args} to the first caplen bytes of data from the packet.
   *
   * (In older versions of libpcap, the behavior when cnt was 0 was undefined;
   * different platforms and devices behaved differently, so code that must work with
   * older versions of libpcap should use -1, nor 0, as the value of cnt.)
   *
   * @param count number of packets.
   * @param handler {@link PacketHandler} callback function.
   * @param args user args.
   * @param <T> args type.
   * @throws BreakException {@link Pcap#breakLoop()} is called.
   * @throws ErrorException Generic error.
   */
  <T> void dispatch(int count, PacketHandler<T> handler, T args) throws BreakException, ErrorException;;

  /**
   * Represent packet statistics from the start of the run to the time of the call.
   *
   * <p>Supported only on live captures, not on {@code PcapOffline}; no statistics are stored in
   * {@code PcapOffline} so no statistics are available when reading from a {@code PcapOffline}
   *
   * @return returns {@link Status} on success.
   * @throws ErrorException There is an error or if this {@link Pcap} doesn't support packet
   *     statistics.
   * @since 1.0.0
   */
  Status status() throws ErrorException;

  /**
   * Force a {@link Pcap#loop(int, PacketHandler, Object)} call to return And throw {@link
   * BreakException} on {@link Pcap#loop(int, PacketHandler, Object)}.
   *
   * @since 1.0.0
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
   * Used to specify a direction that packets will be captured.
   * This method isn't necessarily fully supported on all platforms;
   * some platforms might return an error for all values, and some other
   * platforms might not support {@link Direction#PCAP_D_OUT}.
   *
   * This operation is not supported if a {@code PcapOffline} is being read.
   *
   * Below is list of directions:
   * <ul>
   *     <li>
   *         {@code PCAP_D_INOUT} is the default direction and it will capture packets received by or sent by the device.
   *    </li>
   *     <li>
   *         {@code PCAP_D_IN} only capture packets received by the device.
   *     </li>
   *     <li>
   *         {@code PCAP_D_OUT} only capture packets sent by the device.
   *     </li>
   * </ul>
   *
   * @param direction is one of the constants {@link Direction}.
   */
  void setDirection(Direction direction) throws ErrorException;

  /**
   * Close {@code PcapLive} or {@code PcapOffline}. <br>
   * Note: BPF handle will closed automaticly.
   *
   * @since 1.0.0
   */
  @Override
  void close();

  /**
   * Used to specify a direction that packets will be captured.
   */
  enum Direction {
    PCAP_D_INOUT,
    PCAP_D_IN,
    PCAP_D_OUT
  }
}

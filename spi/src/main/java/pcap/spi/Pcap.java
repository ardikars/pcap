/** This code is licenced under the GPL version 2. */
package pcap.spi;

import java.util.concurrent.TimeoutException;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.exception.error.NotActivatedException;

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
   * Reads the next packet and returns a success/failure indication.
   *
   * <p>Deprecated: use {@link Pcap#nextEx(PacketHeader, PacketBuffer)} instead.
   *
   * @param packetBuffer packet buffer.
   * @param packetHeader packet header.
   * @throws BreakException there are no more packets to read from `savefile`.
   * @throws TimeoutException if packets are being read from a `live capture` and the packet buffer
   *     timeout expired.
   * @throws ErrorException generic exception.
   * @since 1.0.0
   */
  void nextEx(PacketBuffer packetBuffer, PacketHeader packetHeader)
      throws BreakException, TimeoutException, ErrorException;

  /**
   * Reads the next packet and returns a success/failure indication.
   *
   * @param packetHeader packet header.
   * @param packetBuffer packet buffer.
   * @throws BreakException there are no more packets to read from `savefile`.
   * @throws TimeoutException if packets are being read from a `live capture` and the packet buffer
   *     timeout expired.
   * @throws ErrorException generic exception.
   * @since 1.0.0
   */
  void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
      throws BreakException, TimeoutException, ErrorException;

  /**
   * Processes packets from a live capture or {@code PcapLive} until cnt packets are processed, the
   * end of the current bufferful of packets is reached when doing a live capture, the end of the
   * {@code 'savefile'} is reached when reading from a {@code 'savefile'}, {@code Pcap#breakLoop()}
   * is called, or an error occurs. Thus, when doing a live capture, cnt is the maximum number of
   * packets to process before returning, but is not a minimum number; when reading a live capture,
   * only one bufferful of packets is read at a time, so fewer than cnt packets may be processed. A
   * value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when
   * reading a live capture, and causes all the packets in the file to be processed when reading a
   * {@code 'savefile'}.
   *
   * <p>(In older versions of libpcap, the behavior when cnt was 0 was undefined; different
   * platforms and devices behaved differently, so code that must work with older versions of
   * libpcap should use -1, nor 0, as the value of cnt.)
   *
   * <p>callback specifies a {@code PacketHandler} routine to be called with three arguments : a
   * {@code args} which is passed in the user argument to {@code Pcap#loop()} or {@code
   * Pcap#dispatch()}, a const struct pcap_pkthdr pointer pointing to the packet time stamp and
   * lengths, and a {@code args} to the first caplen bytes of data from the packet.
   *
   * <p>(In older versions of libpcap, the behavior when cnt was 0 was undefined; different
   * platforms and devices behaved differently, so code that must work with older versions of
   * libpcap should use -1, nor 0, as the value of cnt.)
   *
   * @param count number of packets.
   * @param handler {@link PacketHandler} callback function.
   * @param args user args.
   * @param <T> args type.
   * @throws BreakException {@link Pcap#breakLoop()} is called.
   * @throws ErrorException Generic error.
   */
  <T> void dispatch(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException;

  /**
   * Represent packet statistics from the start of the run to the time of the call.
   *
   * <p>Supported only on live captures, not on {@code PcapOffline}; no statistics are stored in
   * {@code PcapOffline} so no statistics are available when reading from a {@code PcapOffline}
   *
   * @return returns {@link Statistics} on success.
   * @throws ErrorException There is an error or if this {@link Pcap} doesn't support packet
   *     statistics.
   * @since 1.0.0
   */
  Statistics stats() throws ErrorException;

  /**
   * Represent packet statistics from the start of the run to the time of the call.
   *
   * <p>Supported only on live captures, not on {@code PcapOffline}; no statistics are stored in
   * {@code PcapOffline} so no statistics are available when reading from a {@code PcapOffline}
   *
   * <p>Deprecated: Use {@link Pcap#stats()} instead.
   *
   * @return returns {@link Statistics} on success.
   * @throws ErrorException There is an error or if this {@link Pcap} doesn't support packet
   *     statistics.
   * @since 1.0.0
   */
  @Deprecated
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
  @Deprecated
  void sendPacket(PacketBuffer directBuffer, int size) throws ErrorException;

  /**
   * Deprecated: Use {@link Pcap#sendPacket(PacketBuffer)} instead.
   *
   * @param directBuffer direct buffer.
   * @param size size.
   * @throws ErrorException error exception.
   */
  @Deprecated
  void send(PacketBuffer directBuffer, int size) throws ErrorException;

  /**
   * Deprecated: Use {@link Pcap#sendPacket(PacketBuffer)} instead.
   *
   * @param directBuffer direct buffer.
   * @throws ErrorException error exception.
   */
  @Deprecated
  void send(PacketBuffer directBuffer) throws ErrorException;

  /**
   * Send a raw packet through the network interface.
   *
   * @param directBuffer buffer started from {@link PacketBuffer#readerIndex()} to {@link
   *     PacketBuffer#writerIndex()}.
   * @throws ErrorException generic error.
   */
  void sendPacket(PacketBuffer directBuffer) throws ErrorException;

  /**
   * Used to specify a direction that packets will be captured. This method isn't necessarily fully
   * supported on all platforms; some platforms might return an error for all values, and some other
   * platforms might not support {@link Direction#PCAP_D_OUT}.
   *
   * <p>This operation is not supported if a {@code PcapOffline} is being read.
   *
   * <p>Below is list of directions:
   *
   * <ul>
   *   <li>{@code PCAP_D_INOUT} is the default direction and it will capture packets received by or
   *       sent by the device.
   *   <li>{@code PCAP_D_IN} only capture packets received by the device.
   *   <li>{@code PCAP_D_OUT} only capture packets sent by the device.
   * </ul>
   *
   * @param direction is one of the constants {@link Direction}.
   * @throws ErrorException generic exception.
   */
  void setDirection(Direction direction) throws ErrorException;

  /**
   * Find out out whether a 'savefile' has the native byte order.
   *
   * @return returns {@code true} if a handle is on offline mode ('savefile') and using a different
   *     byte order with current system. For live handle, it's always returns {@code false}.
   * @throws NotActivatedException if called this function on a capture handle that has been created
   *     but not activated.
   */
  boolean isSwapped() throws NotActivatedException;

  /**
   * Get major version number of a 'savefile'. If {@link Pcap} handle is in live mode, this method
   * are not meaningful.
   *
   * @return returns major version of a 'savefile.
   */
  int majorVersion();

  /**
   * Get minor version number of a 'savefile'. If {@link Pcap} handle is in live mode, this method
   * are not meaningful.
   *
   * @return returns minor version of a 'savefile'.
   */
  int minorVersion();

  /**
   * Get snapshot length.
   *
   * @return returns snapshot length.
   */
  int snapshot();

  /**
   * Returns blocking mode. Always returns false if a {@link Pcap} handle in offline handle
   * (savefile).
   *
   * @return returns {@code true} if non blocking, {@code false otherwise}.
   * @throws ErrorException error occurred.
   */
  boolean getNonBlock() throws ErrorException;

  /**
   * Puts a this capture handle into `non-blocking` mode, or takes it out of `non-blocking` mode,
   * depending on whether the nonblock argument is `true` or `false`. It has no effect on
   * `savefiles`. In `non-blocking` mode, an attempt to read from the capture descriptor with {@link
   * Pcap#dispatch(int, PacketHandler, Object)} will, if no packets are currently available to be
   * read, return void; immediately rather than blocking waiting for packets to arrive. {@link
   * Pcap#loop(int, PacketHandler, Object)} will not work in `non-blocking` mode.
   *
   * <p>When {@link Pcap} handle created, a handle is not in non blocking mode.
   *
   * @param blocking `true` for enable non blocking mode, `false` otherwise.
   * @throws ErrorException throwing some error when calling this method.
   */
  void setNonBlock(boolean blocking) throws ErrorException;

  /**
   * Close {@code PcapLive} or {@code PcapOffline}. <br>
   * Note: BPF handle will closed automaticly.
   *
   * @since 1.0.0
   */
  @Override
  void close();

  /**
   * Create pointer to given type and automatically deallocate when this handler has been closed.
   *
   * @see Pcap#close()
   * @param cls a class, ex {@link PacketHeader} and {@link PacketBuffer}.
   * @param <T> pointer type.
   * @return returns {@code <T>} instance.
   */
  <T> T allocate(Class<T> cls) throws IllegalArgumentException;

  /** Used to specify a direction that packets will be captured. */
  enum Direction {
    PCAP_D_INOUT,
    PCAP_D_IN,
    PCAP_D_OUT;

    private static final Direction[] VALUES = values();

    /**
     * Get pcap direction from string.
     *
     * @param value string value.
     * @return returns {@link Direction}.
     */
    public static Direction fromString(String value) {
      for (Direction direction : VALUES) {
        if (direction.name().equals(value)) {
          return direction;
        }
      }
      return PCAP_D_INOUT;
    }
  }

  /** Unix pcap api extension. */
  interface UnixPcap {

    /**
     * Get a file descriptor on which a select() can be done for a live capture.
     *
     * <p>Some network devices do not support select(), poll(), epoll_wait(), kevent(), or other
     * such call to wait for it to be possible to read packets without blocking, so (-1) is returned
     * for those devices. In that case, those calls must be given a timeout less than or equal to
     * the timeout returned by selectableFd() for the device for which selectableFd() returned (-1),
     * the device must be put in non-blocking mode with a call to setNonBlock(true), and an attempt
     * must always be made to read packets from the device when the call returns. If
     * requiredSelectTimeout returns NULL, it is not possible to wait for packets to arrive on the
     * device in an event loop.
     *
     * <p>Note that a device on which a read can be done without blocking may, on some platforms,
     * not have any packets to read if the packet buffer timeout has expired. A call to dispatch or
     * nextEx will return 0 in this case, but will not block.
     *
     * @return returns file descriptor associated with the pcap handle, otherwise -1 on error.
     */
    int selectableFd();

    /**
     * Returns {@link Timestamp} containing a value that must be used as the minimum timeout in
     * select(), poll(), epoll_wait(), and kevent() calls if selectableFd() returns -1.
     *
     * <p>The timeout that should be used in those calls must be no larger than the smallest of all
     * timeouts returned by requiredSelectTimeout() for devices from which packets will be captured.
     *
     * @return returns null on error, otherwise {@link Timestamp}.
     */
    Timestamp requiredSelectTimeout();
  }

  /** Windows pcap api extension. */
  interface WinPcap {

    /**
     * Get the handle of the event associated with the pcap handle.
     *
     * @return returns event handle.
     */
    Handle event();

    interface Handle {

      /**
       * Returns memory address for this handle.
       *
       * @return returns memory address.
       */
      long address();
    }
  }
}

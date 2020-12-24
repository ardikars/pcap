/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.exception.error.NotActivatedException;

/**
 * A handle for {@code pcap} instance.
 *
 * @since 1.0.0
 */
public interface Pcap extends AutoCloseable {

  /**
   * Open {@link Dumper} handler for writing the packets to {@code savefile} (Create/Override
   * existing file).
   *
   * @param file location of {@code savefile} will saved.
   * @return returns new {@link Dumper} handle.
   * @throws ErrorException generic exception.
   * @since 1.0.0
   */
  Dumper dumpOpen(String file) throws ErrorException;

  /**
   * Open {@code savefile} or create the new one if it's doesn't exist.
   *
   * @param file location of saved file.
   * @return returns new {@link Dumper} handle.
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
   * Read the next packet (by calling {@link Pcap#dispatch(int, PacketHandler, Object)}) with a cnt
   * of 1) and returns a {@link PacketBuffer}. The {@link PacketBuffer} and {@link PacketHeader} is
   * not freed by the caller, and not not guaranteed to be valid after the next call to {@link
   * Pcap#nextEx(PacketHeader, PacketBuffer)}, {@link Pcap#next(PacketHeader)}, {@link
   * Pcap#loop(int, PacketHandler, Object)}, or {@link Pcap#dispatch(int, PacketHandler, Object)}.
   * If the code needs it to remain valid, it must make a copy of it. The {@link PacketHeader}
   * pointed to by {@code header} is filled in with the appropriate values for the packet.
   *
   * @param header header.
   * @return returns {@link PacketBuffer} appropriate with for the {@link PacketHeader}.
   */
  PacketBuffer next(PacketHeader header);

  /**
   * Reads the next packet and returns a success/failure indication. The {@link PacketBuffer} and
   * {@link PacketHeader} is not freed by the caller, and not not guaranteed to be valid after the
   * next call to {@link Pcap#nextEx(PacketHeader, PacketBuffer)}, {@link Pcap#next(PacketHeader)},
   * {@link Pcap#loop(int, PacketHandler, Object)}, or {@link Pcap#dispatch(int, PacketHandler,
   * Object)}. If the code needs it to remain valid, it must make a copy of it.
   *
   * <p>The {@link PacketHeader} pointed to by {@code header} and the {@link PacketBuffer} pointer
   * by {@code buffer} is filled in with the appropriate values for the packet.
   *
   * @param packetHeader header.
   * @param packetBuffer buffer.
   * @throws BreakException there are no more packets to read from {@code savefile}.
   * @throws TimeoutException if packets are being read from a `live capture` and the packet buffer
   *     timeout expired.
   * @throws ErrorException generic exception.
   * @since 1.0.0
   */
  void nextEx(PacketHeader packetHeader, PacketBuffer packetBuffer)
      throws BreakException, TimeoutException, ErrorException;

  /**
   * Processes packets from a live capture or {@code PcapLive} until cnt packets are processed.
   *
   * @param count number of packets.
   * @param handler {@link PacketHandler} callback function.
   * @param args user args.
   * @param <T> args type.
   * @throws BreakException {@link Pcap#breakLoop()} is called.
   * @throws ErrorException Generic error.
   * @throws TimeoutException timeout.
   */
  <T> void dispatch(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException, TimeoutException;

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
   * Force a {@link Pcap#loop(int, PacketHandler, Object)} or {@link Pcap#dispatch(int,
   * PacketHandler, Object)} call to return And throw {@link BreakException} on {@link
   * Pcap#loop(int, PacketHandler, Object)}.
   *
   * @since 1.0.0
   */
  void breakLoop();

  /**
   * Send a raw packet through the network interface.
   *
   * @see <a href="https://www.tcpdump.org/manpages/pcap_inject.3pcap.html">pcap_inject</a>
   * @param directBuffer buffer started from {@link PacketBuffer#readerIndex()} to {@link
   *     PacketBuffer#writerIndex()}.
   * @throws ErrorException generic error.
   * @since 1.0.0
   */
  void sendPacket(PacketBuffer directBuffer) throws ErrorException;

  /**
   * Sends a raw packet through the network interface; directBuffer points to the data of the
   * packet, including the link-layer header, and size is the number of bytes in the packet.
   *
   * @see <a href="https://www.tcpdump.org/manpages/pcap_inject.3pcap.html">pcap_inject</a>
   * @param directBuffer buffer started from {@link PacketBuffer#readerIndex()} to {@link
   *     PacketBuffer#writerIndex()}.
   * @return returns the number of bytes written on success and throws {@link ErrorException} on
   *     failure.
   * @throws ErrorException error exception.
   * @since 1.0.0
   */
  int inject(PacketBuffer directBuffer) throws ErrorException;

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
   * @since 1.0.0
   */
  void setDirection(Direction direction) throws ErrorException;

  /**
   * Find out out whether a {@code savefile} has the native byte order.
   *
   * @return returns {@code true} if a handle is on offline mode ({@code savefile}) and using a
   *     different byte order with current system. For live handle, it's always returns {@code
   *     false}.
   * @throws NotActivatedException if called this function on a capture handle that has been created
   *     but not activated.
   * @since 1.0.0
   */
  boolean isSwapped() throws NotActivatedException;

  /**
   * Get the time stamp precision returned in captures.
   *
   * @return returns {@link Timestamp.Precision#MICRO} or {@link Timestamp.Precision#NANO}, which
   *     indicates that pcap captures contains time stamps in microseconds or nanoseconds
   *     respectively.
   * @since 1.0.0
   */
  Timestamp.Precision getTimestampPrecision();

  /**
   * Get major version number of a {@code savefile}. If {@link Pcap} handle is in live mode, this
   * method are not meaningful.
   *
   * @return returns major version of a {@code savefile}.
   * @since 1.0.0
   */
  int majorVersion();

  /**
   * Get minor version number of a {@code savefile}. If {@link Pcap} handle is in live mode, this
   * method are not meaningful.
   *
   * @return returns minor version of a {@code savefile}.
   * @since 1.0.0
   */
  int minorVersion();

  /**
   * Get snapshot length.
   *
   * @return returns snapshot length.
   * @since 1.0.0
   */
  int snapshot();

  /**
   * Returns blocking mode. Always returns false if a {@link Pcap} handle in offline handle ({@code
   * savefile}).
   *
   * @return returns {@code true} if non blocking, {@code false otherwise}.
   * @throws ErrorException error occurred.
   * @since 1.0.0
   */
  boolean getNonBlock() throws ErrorException;

  /**
   * Puts a this capture handle into {@code non-blocking} mode, or takes it out of {@code
   * non-blocking} mode, depending on whether the {@code blocking} argument is {@code true} or
   * {@code false}. It has no effect on {@code savefiles}. In {@code non-blocking} mode, an attempt
   * to read from the capture descriptor with {@link Pcap#dispatch(int, PacketHandler, Object)}
   * will, if no packets are currently available to be read, return void; immediately rather than
   * blocking waiting for packets to arrive. {@link Pcap#loop(int, PacketHandler, Object)} will not
   * work in {@code non-blocking} mode.
   *
   * <p>When {@link Pcap} handle created, a handle is not in non blocking mode.
   *
   * @param blocking {@code true} for enable non blocking mode, {@code false} otherwise.
   * @throws ErrorException throwing some error when calling this method.
   * @since 1.0.0
   */
  void setNonBlock(boolean blocking) throws ErrorException;

  /**
   * Get link-layer header type for for both {@link Service#live(Interface, Service.LiveOptions)}
   * and {@link Service#offline(String, Service.OfflineOptions)}.
   *
   * @return returns the link-layer header type.
   */
  int datalink();

  /**
   * Close {@code PcapLive} or {@code PcapOffline}.
   *
   * @since 1.0.0
   */
  @Override
  void close();

  /**
   * Create pointer to given type.
   *
   * @param cls a class, ex {@link PacketHeader} and {@link PacketBuffer}.
   * @param <T> pointer type.
   * @return returns {@code <T>} instance.
   * @since 1.0.0
   */
  <T> T allocate(Class<T> cls) throws IllegalArgumentException;

  /**
   * Used to specify a direction that packets will be captured.
   *
   * @since 1.0.0
   */
  enum Direction {
    /**
     * Incoming and Outgoing packet's.
     *
     * @since 1.0.0
     */
    PCAP_D_INOUT,
    /**
     * Incoming packet's.
     *
     * @since 1.0.0
     */
    PCAP_D_IN,
    /**
     * Outgoing packet's.
     *
     * @since 1.0.0
     */
    PCAP_D_OUT;

    private static final Direction[] VALUES = values();

    /**
     * This function will removed on 1.1.x and above.
     *
     * <p>Get pcap direction from string.
     *
     * @param value string value.
     * @return returns {@link Direction}.
     * @since 1.0.0
     */
    @Deprecated
    public static Direction fromString(String value) {
      for (int i = 0; i < VALUES.length; i++) {
        if (VALUES[i].name().equals(value)) {
          return VALUES[i];
        }
      }
      return PCAP_D_INOUT;
    }
  }
}

/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import java.util.Iterator;
import java.util.ServiceLoader;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;

/**
 * Pcap service.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public interface Service {

  /**
   * Get unique service name.
   *
   * @return returns unique service name.
   * @since 1.0.0
   */
  String name();

  /**
   * Get native pcap library version.
   *
   * @return returns native pcap library version.
   * @since 1.0.0
   */
  String version();

  /**
   * Find all interfaces on your system.
   *
   * <p>Note that there may be network devices that cannot be opened by the process calling this.
   *
   * @return returns iterable {@link Interface}'s.
   * @throws ErrorException generic error.
   * @since 1.0.0
   */
  Interface interfaces() throws ErrorException;

  /**
   * Open offline handle.
   *
   * @param source file.
   * @param options pcap offline option.
   * @return returns {@link Pcap} live handle.
   * @throws ErrorException generic exeception.
   * @since 1.0.0
   */
  Pcap offline(String source, OfflineOptions options) throws ErrorException;

  /**
   * Open live capture handle.
   *
   * @param source interface.
   * @param options pcap live option.
   * @return returns {@link Pcap} offline handle.
   * @throws InterfaceNotSupportTimestampTypeException timestamp type not supported by interface.
   * @throws InterfaceNotUpException interface is not up.
   * @throws RadioFrequencyModeNotSupportedException radio frequency mode is not supported.
   * @throws ActivatedException a handle is already activated or need to activated.
   * @throws PermissionDeniedException you have no permission to open live handle with current user.
   * @throws NoSuchDeviceException no such device can be use to open live handle.
   * @throws PromiscuousModePermissionDeniedException you have no permission to enable promiscuous
   *     mode.
   * @throws ErrorException generic error.
   * @throws TimestampPrecisionNotSupportedException timestamp precision not supported.
   * @since 1.0.0
   */
  Pcap live(Interface source, LiveOptions options)
      throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
          TimestampPrecisionNotSupportedException;

  /**
   * Options for opening {@code savefile} by {@link Service#offline(String, OfflineOptions)}.
   *
   * @since 1.0.0
   */
  interface OfflineOptions {

    /**
     * Get timestamp precision options.
     *
     * @return returns {@link Timestamp.Precision}.
     * @since 1.0.0
     */
    Timestamp.Precision timestampPrecision();

    /**
     * Set timestamp precicion options.
     *
     * @param timestampPrecision timestamp precision.
     * @return returns this instance.
     * @since 1.0.0
     */
    OfflineOptions timestampPrecision(Timestamp.Precision timestampPrecision);
  }

  /**
   * Options for opening live capture handle by {@link Service#live(Interface, LiveOptions)}.
   *
   * @since 1.0.0
   */
  interface LiveOptions {

    /**
     * Get snapshot length.
     *
     * @return returns snapshot length.
     * @since 1.0.0
     */
    int snapshotLength();

    /**
     * If, when capturing, you capture the entire contents of the packet, that requires more CPU
     * time to copy the packet to your application, more disk and possibly network bandwidth to
     * write the packet data to a file, and more disk space to save the packet. If you don't need
     * the entire contents of the packet - for example, if you are only interested in the TCP
     * headers of packets - you can set the "snapshot length" for the capture to an appropriate
     * value. If the snapshot length is less than the size of a packet that is captured, only the
     * first snapshot length bytes of that packet will be captured and provided as packet data. A
     * snapshot length of 65535 should be sufficient, on most if not all networks, to capture all
     * the data available from the packet.
     *
     * @see <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap.3pcap.html"</a>
     * @param snapshotLength shapshot length.
     * @return returns this instance.
     * @since 1.0.0
     */
    LiveOptions snapshotLength(int snapshotLength);

    /**
     * Get promiscuous mode options.
     *
     * @return returns {@code true} if in promiscuous mode, {@code false} otherwise.
     * @since 1.0.0
     */
    boolean isPromiscuous();

    /**
     * On broadcast LANs such as Ethernet, if the network isn't switched, or if the adapter is
     * connected to a "mirror port" on a switch to which all packets passing through the switch are
     * sent, a network adapter receives all packets on the LAN, including unicast or multicast
     * packets not sent to a network address that the network adapter isn't configured to recognize.
     * Normally, the adapter will discard those packets; however, many network adapters support
     * "promiscuous mode", which is a mode in which all packets, even if they are not sent to an
     * address that the adapter recognizes, are provided to the host. This is useful for passively
     * capturing traffic between two or more other hosts for analysis. Note that even if an
     * application does not set promiscuous mode, the adapter could well be in promiscuous mode for
     * some other reason. For now, this doesn't work on the "any" device; if an argument of "any" is
     * supplied, the setting of promiscuous mode is ignored.
     *
     * @see <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap.3pcap.html"</a>
     * @param promiscuous promiscuous mode.
     * @return returns this instance.
     * @since 1.0.0
     */
    LiveOptions promiscuous(boolean promiscuous);

    /**
     * Get radio frequency monitor mode options.
     *
     * @return returns {@code true} if in {@code rfmon}, {@code false} otherwise.
     * @since 1.0.0
     */
    boolean isRfmon();

    /**
     * On IEEE 802.11 wireless LANs, even if an adapter is in promiscuous mode, it will supply to
     * the host only frames for the network with which it's associated. It might also supply only
     * data frames, not management or control frames, and might not provide the 802.11 header or
     * radio information pseudo-header for those frames. In "monitor mode", sometimes also called
     * "rfmon mode" (for "Radio Frequency MONitor"), the adapter will supply all frames that it
     * receives, with 802.11 headers, and might supply a pseudo-header with radio information about
     * the frame as well. Note that in monitor mode the adapter might disassociate from the network
     * with which it's associated, so that you will not be able to use any wireless networks with
     * that adapter. This could prevent accessing files on a network server, or resolving host names
     * or network addresses, if you are capturing in monitor mode and are not connected to another
     * network with another adapter.
     *
     * @see <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap.3pcap.html"</a>
     * @param rfmon {@code true} for {@code rfmon}, {@code false} non {@code non rfmon}.
     * @return returns this instance.
     * @since 1.0.0
     */
    LiveOptions rfmon(boolean rfmon);

    /**
     * Get read timeout options in millisecond.
     *
     * @return returns read timeout in millisecond.
     * @since 1.0.0
     */
    int timeout();

    /**
     * If, when capturing, packets are delivered as soon as they arrive, the application capturing
     * the packets will be woken up for each packet as it arrives, and might have to make one or
     * more calls to the operating system to fetch each packet. If, instead, packets are not
     * delivered as soon as they arrive, but are delivered after a short delay (called a "packet
     * buffer timeout"), more than one packet can be accumulated before the packets are delivered,
     * so that a single wakeup would be done for multiple packets, and each set of calls made to the
     * operating system would supply multiple packets, rather than a single packet. This reduces the
     * per-packet CPU overhead if packets are arriving at a high rate, increasing the number of
     * packets per second that can be captured. The packet buffer timeout is required so that an
     * application won't wait for the operating system's capture buffer to fill up before packets
     * are delivered; if packets are arriving slowly, that wait could take an arbitrarily long
     * period of time. Not all platforms support a packet buffer timeout; on platforms that don't,
     * the packet buffer timeout is ignored. A zero value for the timeout, on platforms that support
     * a packet buffer timeout, will cause a read to wait forever to allow enough packets to arrive,
     * with no timeout. A negative value is invalid; the result of setting the timeout to a negative
     * value is unpredictable. NOTE: the packet buffer timeout cannot be used to cause calls that
     * read packets to return within a limited period of time, because, on some platforms, the
     * packet buffer timeout isn't supported, and, on other platforms, the timer doesn't start until
     * at least one packet arrives. This means that the packet buffer timeout should NOT be used,
     * for example, in an interactive application to allow the packet capture loop to "poll" for
     * user input periodically, as there's no guarantee that a call reading packets will return
     * after the timeout expires even if no packets have arrived.
     *
     * @see <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap.3pcap.html"</a>
     * @param timeout read timeout in millisecond .
     * @return returns this instance.
     * @since 1.0.0
     */
    LiveOptions timeout(int timeout);

    /**
     * Get timestamp type options.
     *
     * @return returns {@link Timestamp.Type} options.
     * @since 1.0.0
     */
    Timestamp.Type timestampType();

    /**
     * On some platforms, the time stamp given to packets on live captures can come from different
     * sources that can have different resolutions or that can have different relationships to the
     * time values for the current time supplied by routines on the native operating system.
     *
     * @see <a href="https://www.tcpdump.org/manpages/pcap-tstamp.7.html">pcap-tstamp.7.html</a>
     * @see <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap.3pcap.html"</a>
     * @param timestampType timestamp type.
     * @return returns this instance.
     * @since 1.0.0
     */
    LiveOptions timestampType(Timestamp.Type timestampType);

    /**
     * Get immediate mode options.
     *
     * @return returns {@code true} if in immediate mode, {@code false} otherwise.
     * @since 1.0.0
     */
    boolean isImmediate();

    /**
     * In immediate mode, packets are always delivered as soon as they arrive, with no buffering.
     *
     * @param immediate {@code true} for immediate mode, {@code false} otherwise.
     * @return returns this instance.
     * @since 1.0.0
     */
    LiveOptions immediate(boolean immediate);

    /**
     * Get buffer size options.
     *
     * @return returns buffer size options.
     * @since 1.0.0
     */
    int bufferSize();

    /**
     * Packets that arrive for a capture are stored in a buffer, so that they do not have to be read
     * by the application as soon as they arrive. On some platforms, the buffer's size can be set; a
     * size that's too small could mean that, if too many packets are being captured and the
     * snapshot length doesn't limit the amount of data that's buffered, packets could be dropped if
     * the buffer fills up before the application can read packets from it, while a size that's too
     * large could use more non-pageable operating system memory than is necessary to prevent
     * packets from being dropped.
     *
     * @see <a href="https://www.tcpdump.org/manpages/pcap.3pcap.html">pcap.3pcap.html"</a>
     * @param bufferSize buffer size.
     * @return returns this instance.
     * @since 1.0.0
     */
    LiveOptions bufferSize(int bufferSize);

    /**
     * Get timestamp precision options.
     *
     * @return returns {@link Timestamp.Precision} options.
     * @since 1.0.0
     */
    Timestamp.Precision timestampPrecision();

    /**
     * Set timestamp precision options.
     *
     * @param timestampPrecision timestamp precision.
     * @return returns this instance.
     * @since 1.0.0
     */
    LiveOptions timestampPrecision(Timestamp.Precision timestampPrecision);
  }

  /**
   * A creator class for creating {@link Service} instance by {@link ServiceLoader}.
   *
   * @since 1.0.0
   */
  class Creator {

    private static Service[] PROVIDERS = new Service[0];

    static {
      ServiceLoader<Service> services =
          ServiceLoader.load(Service.class, Service.class.getClassLoader());
      Iterator<Service> iterator = services.iterator();
      while (iterator.hasNext()) {
        Service service = iterator.next();
        Service[] newServices = new Service[PROVIDERS.length + 1];
        System.arraycopy(PROVIDERS, 0, newServices, 0, PROVIDERS.length);
        newServices[PROVIDERS.length] = service;
        PROVIDERS = newServices;
      }
    }

    private Creator() {}

    /**
     * Create {@link Service} provider instance.
     *
     * @param name service name.
     * @return returns new {@link Service} instance.
     * @throws ErrorException service provider is not found for given name.
     * @since 1.0.0
     */
    public static Service create(String name) throws ErrorException {
      for (int i = 0; i < PROVIDERS.length; i++) {
        if (PROVIDERS[i].name().equals(name)) {
          return PROVIDERS[i];
        }
      }
      throw new ErrorException("No service provider implementation for (" + name + ").");
    }
  }
}

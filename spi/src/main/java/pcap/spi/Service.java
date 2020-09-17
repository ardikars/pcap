/** This code is licenced under the GPL version 2. */
package pcap.spi;

import java.net.Inet4Address;
import java.net.Inet6Address;
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

  class Creator {

    private Creator() {}

    /**
     * Create {@link Service} provider inctance.
     *
     * @param name service name.
     * @return returns new {@link Service} instance.
     * @throws ErrorException service provider is not found for given type.
     */
    public static Service create(String name) throws ErrorException {
      ServiceLoader<Service> loader = ServiceLoader.load(Service.class);
      Iterator<Service> iterator = loader.iterator();
      while (iterator.hasNext()) {
        Service service = iterator.next();
        if (service.name().equals(name)) {
          return service;
        }
      }
      throw new ErrorException("No service provider implementation for (" + name + ").");
    }
  }

  /**
   * Get unique service name.
   *
   * @return returns unique service name.
   */
  String name();

  /**
   * Get native pcap library version.
   *
   * @return returns native pcap library version.
   */
  String version();

  /**
   * Find all interfaces on your system.
   *
   * @return returns iterable {@link Interface}'s.
   * @throws ErrorException generic error.
   */
  Interface lookupInterfaces() throws ErrorException;

  /**
   * Find all interfaces on your system.
   *
   * @return returns iterable {@link Interface}'s.
   * @throws ErrorException generic error.
   */
  Interface interfaces() throws ErrorException;

  /**
   * Lookup {@link Inet4Address} from {@link Interface}.
   *
   * @param source {@link Interface}.
   * @return returns {@link Inet4Address}.
   * @throws ErrorException address not found.
   */
  @Deprecated
  Inet4Address lookupInet4Address(Interface source) throws ErrorException;

  /**
   * Lookup {@link Inet6Address} from {@link Interface}.
   *
   * @param source {@link Interface}.
   * @return returns {@link Inet6Address}.
   * @throws ErrorException address not found.
   */
  @Deprecated
  Inet6Address lookupInet6Address(Interface source) throws ErrorException;

  /**
   * Open offline handle.
   *
   * @param source file.
   * @param options pcap offline option.
   * @return returns {@link Pcap} live handle.
   * @throws ErrorException generic exeception.
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
   */
  Pcap live(Interface source, LiveOptions options)
      throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
          TimestampPrecisionNotSupportedException;

  interface OfflineOptions {

    /**
     * Get timestamp precision options.
     *
     * @return returns {@link Timestamp.Precision}.
     */
    Timestamp.Precision timestampPrecision();

    /**
     * Set timestamp precicion options.
     *
     * @param timestampPrecision timestamp precision.
     * @return returns this instance.
     */
    OfflineOptions timestampPrecision(Timestamp.Precision timestampPrecision);
  }

  interface LiveOptions {

    /**
     * Get snapshot length options.
     *
     * @return returns snapshot length.
     */
    int snapshotLength();

    /**
     * Set snapshot length options.
     *
     * @param snapshotLength shapshot length.
     * @return returns this instance.
     */
    LiveOptions snapshotLength(int snapshotLength);

    /**
     * Get promiscuous mode options.
     *
     * @return returns {@code true} if in promiscuous mode, {@code false} otherwise.
     */
    boolean isPromiscuous();

    /**
     * Set promiscuous mode options.
     *
     * @param promiscuous promiscuous mode.
     * @return returns this instance.
     */
    LiveOptions promiscuous(boolean promiscuous);

    /**
     * Get radio frequency monitor mode options.
     *
     * @return returns {@code true} if in {@code rfmon}, {@code false} otherwise.
     */
    boolean isRfmon();

    /**
     * Set radio frequency monitor mode options.
     *
     * @param rfmon {@code true} for {@code rfmon}, {@code false} non {@code non rfmon}.
     * @return returns this instance.
     */
    LiveOptions rfmon(boolean rfmon);

    /**
     * Get read timeout options in millisecond.
     *
     * @return returns read timeout in millisecond.
     */
    int timeout();

    /**
     * Set read timeout options in millisecond.
     *
     * @param timeout read timeout in millisecond .
     * @return returns this instance.
     */
    LiveOptions timeout(int timeout);

    /**
     * Get timestamp type options.
     *
     * @return returns {@link Timestamp.Type} options.
     */
    Timestamp.Type timestampType();

    /**
     * Set tiomestamp type options.
     *
     * @param timestampType timestamp type.
     * @return returns this instance.
     */
    LiveOptions timestampType(Timestamp.Type timestampType);

    /**
     * Get immediate mode options.
     *
     * @return returns {@code true} if in immediate mode, {@code false} otherwise.
     */
    boolean isImmediate();

    /**
     * Set immediate mode options.
     *
     * @param immediate {@code true} for immediate mode, {@code false} otherwise.
     * @return returns this instance.
     */
    LiveOptions immediate(boolean immediate);

    /**
     * Get buffer size options.
     *
     * @return returns buffer size options.
     */
    int bufferSize();

    /**
     * Set buffer size options.
     *
     * @param bufferSize buffer size.
     * @return returns this instance.
     */
    LiveOptions bufferSize(int bufferSize);

    /**
     * Get timestamp precision options.
     *
     * @return returns {@link Timestamp.Precision} options.
     */
    Timestamp.Precision timestampPrecision();

    /**
     * Set timestamp precision options.
     *
     * @param timestampPrecision timestamp precision.
     * @return returns this instance.
     */
    LiveOptions timestampPrecision(Timestamp.Precision timestampPrecision);
  }

  class NoService implements Service {

    @Override
    public String name() {
      return "NoService";
    }

    @Override
    public String version() {
      return "0.0.0";
    }

    @Override
    public Interface lookupInterfaces() throws ErrorException {
      throw new ErrorException("No API implementation.");
    }

    @Override
    public Interface interfaces() throws ErrorException {
      throw new ErrorException("No API implementation.");
    }

    @Override
    public Inet4Address lookupInet4Address(Interface source) throws ErrorException {
      throw new ErrorException("No API implementation.");
    }

    @Override
    public Inet6Address lookupInet6Address(Interface source) throws ErrorException {
      throw new ErrorException("No API implementation.");
    }

    @Override
    public Pcap offline(String source, OfflineOptions options) throws ErrorException {
      throw new ErrorException("No API implementation.");
    }

    @Override
    public Pcap live(Interface source, LiveOptions options)
        throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
            RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
            NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
            TimestampPrecisionNotSupportedException {
      throw new ErrorException("No API implementation.");
    }
  }
}

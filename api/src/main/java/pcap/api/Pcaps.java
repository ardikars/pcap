/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.NativeTypes;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Iterator;
import java.util.stream.StreamSupport;
import pcap.api.internal.PcapConstant;
import pcap.api.internal.PcapInterface;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.net.MacAddress;
import pcap.common.util.Platforms;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.WarningException;
import pcap.spi.exception.error.*;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class Pcaps {

  abstract Pcap open() throws Throwable;

  /**
   * Open offline handle.
   *
   * @param pcapOffline pcap offline option.
   * @return returns {@link Pcap} live handle.
   * @throws ErrorException
   */
  public static Pcap offline(PcapOffline pcapOffline) throws ErrorException {
    return pcapOffline.open();
  }

  /**
   * Open live capture handle.
   *
   * @param pcapLive pcap live option.
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
  public static Pcap live(PcapLive pcapLive)
      throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
          TimestampPrecisionNotSupportedException {
    return pcapLive.open();
  }

  /**
   * Find all interfaces on your system.
   *
   * @return returns iterable {@link Interface}'s.
   * @throws ErrorException generic error.
   */
  public static Interface findInterfaces() throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      Pointer<Pointer<pcap_mapping.pcap_if>> pointer =
          PcapConstant.SCOPE.allocate(LayoutType.ofStruct(pcap_mapping.pcap_if.class).pointer());
      Pointer<Byte> errbuf =
          PcapConstant.SCOPE.allocate(NativeTypes.INT8, PcapConstant.ERRBUF_SIZE);
      int result = PcapConstant.MAPPING.pcap_findalldevs(pointer, errbuf);
      if (result != PcapConstant.OK) {
        throw new ErrorException(Pointer.toString(errbuf));
      }
      pcap_mapping.pcap_if pcap_if = pointer.get().get();
      Interface devices = new PcapInterface(pcap_if);
      PcapConstant.MAPPING.pcap_freealldevs(pointer.get());
      return devices;
    }
  }

  /**
   * Find interface by name.
   *
   * @param name interface name.
   * @return returns {@link Interface}.
   * @throws ErrorException interface not found.
   */
  private Interface findInterfaceByName(String name) throws ErrorException {
    Interface interfaces = findInterfaces();
    Iterator<Interface> interfaceIterator = interfaces.iterator();
    while (interfaceIterator.hasNext()) {
      Interface next = interfaceIterator.next();
      if (next.name().equalsIgnoreCase(name)) {
        return next;
      }
    }
    throw new ErrorException("Interface not found");
  }

  /**
   * Lookup interface can be used to open {@link Pcap} live handle.
   *
   * @return returns {@link Interface}.
   * @throws ErrorException generic error.
   */
  public static Interface lookupInterface() throws ErrorException {
    synchronized (PcapConstant.LOCK) {
      Pointer<Byte> errbuf =
          PcapConstant.SCOPE.allocate(NativeTypes.INT8, PcapConstant.ERRBUF_SIZE);
      Pointer<Byte> device = PcapConstant.MAPPING.pcap_lookupdev(errbuf);
      if (device == null || device.isNull()) {
        throw new ErrorException(Pointer.toString(errbuf));
      }
      String deviceName = Pointer.toString(device);
      Interface pcapInterface =
          StreamSupport.stream(findInterfaces().spliterator(), false)
              .filter(iface -> deviceName.equals(iface.name()))
              .findFirst()
              .get();
      return pcapInterface;
    }
  }

  /**
   * Get mac address for given {@link Interface}.
   *
   * @param source interface.
   * @return returns {@link MacAddress}.
   * @throws ErrorException generic error.
   */
  public static MacAddress lookupMacAddress(Interface source) throws ErrorException {
    if (Platforms.isWindows()) {
      throw new WarningException(
          "Couldn't get mac address for " + source.name() + ": Not supported yet.");
    }
    try {
      return MacAddress.valueOf(NetworkInterface.getByName(source.name()).getHardwareAddress());
    } catch (SocketException e) {
      throw new ErrorException(e.getMessage());
    }
  }

  /**
   * Get native pcap library version.
   *
   * @return returns native pcap library version.
   */
  public static String version() {
    synchronized (PcapConstant.LOCK) {
      return Pointer.toString(PcapConstant.MAPPING.pcap_lib_version());
    }
  }
}

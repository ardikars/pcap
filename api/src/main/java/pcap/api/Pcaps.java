/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.NativeTypes;
import java.foreign.Scope;
import java.foreign.memory.Array;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Optional;
import java.util.stream.StreamSupport;
import pcap.api.internal.PcapInterface;
import pcap.api.internal.foreign.mapping.IphlpapiMapping;
import pcap.api.internal.foreign.mapping.PcapMapping;
import pcap.api.internal.foreign.pcap_header;
import pcap.api.internal.foreign.struct.windows_structs;
import pcap.common.annotation.Inclubating;
import pcap.common.net.Inet4Address;
import pcap.common.net.Inet6Address;
import pcap.common.net.MacAddress;
import pcap.common.util.Platforms;
import pcap.spi.Address;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class Pcaps {

  /**
   * Open offline handle.
   *
   * @param pcapOffline pcap offline option.
   * @return returns {@link Pcap} live handle.
   * @throws ErrorException generic exeception.
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
  public static Interface lookupInterfaces() throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<Pointer<pcap_header.pcap_if>> pointer =
            scope.allocate(LayoutType.ofStruct(pcap_header.pcap_if.class).pointer());
        Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapMapping.ERRBUF_SIZE);
        int result = PcapMapping.MAPPING.pcap_findalldevs(pointer, errbuf);
        if (result != PcapMapping.OK) {
          throw new ErrorException(Pointer.toString(errbuf));
        }
        pcap_header.pcap_if pcap_if = pointer.get().get();
        Interface devices = new PcapInterface(pcap_if);
        PcapMapping.MAPPING.pcap_freealldevs(pointer.get());
        return devices;
      }
    }
  }

  /**
   * Find interface by name.
   *
   * @param name interface name.
   * @return returns {@link Interface}.
   * @throws ErrorException interface not found.
   */
  public static Interface lookupInterface(String name) throws ErrorException {
    Interface interfaces = lookupInterfaces();
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
   * <p>This functions is deprecated, please use {@link Pcaps#lookupInterfaces()} instead.
   * @see <a link="https://github.com/ardikars/pcap/issues/30">Github Issue: #30</a>
   *
   * @return returns {@link Interface}.
   * @throws ErrorException generic error.
   */
  @Deprecated
  public static Interface lookupInterface() throws ErrorException {
    synchronized (PcapMapping.LOCK) {
      try (Scope scope = Scope.globalScope().fork()) {
        Pointer<Byte> errbuf = scope.allocate(NativeTypes.INT8, PcapMapping.ERRBUF_SIZE);
        Pointer<Byte> device = PcapMapping.MAPPING.pcap_lookupdev(errbuf);
        if (device == null || device.isNull()) {
          throw new ErrorException(Pointer.toString(errbuf));
        }
        String deviceName = Pointer.toString(device);
        Optional<Interface> optional =
            StreamSupport.stream(lookupInterfaces().spliterator(), false)
                .filter(iface -> deviceName.equals(iface.name()))
                .findFirst();
        if (!optional.isPresent()) {
          throw new ErrorException("Device not found!");
        }
        return optional.get();
      }
    }
  }

  /**
   * Get mac address for given {@link Interface}.
   *
   * @param source interface.
   * @return returns {@link MacAddress} for given interface.
   * @throws ErrorException error occured.
   */
  public static MacAddress lookupMacAddress(Interface source) throws ErrorException {
    if (Platforms.isWindows()) {
      Scope scope = Scope.globalScope().fork();
      Pointer<windows_structs._IP_ADAPTER_INFO> adapterInfo =
          scope.allocate(LayoutType.ofStruct(windows_structs._IP_ADAPTER_INFO.class));
      Pointer<Long> length = scope.allocate(NativeTypes.LONG);
      length.set(adapterInfo.type().bytesSize());
      if (IphlpapiMapping.MAPPING.GetAdaptersInfo(adapterInfo, length) == 111) {
        scope.close();
        scope = Scope.globalScope().fork(); // new scope
        adapterInfo = scope.allocate(LayoutType.ofStruct(windows_structs._IP_ADAPTER_INFO.class));
        if (adapterInfo == null || adapterInfo.isNull()) {
          scope.close();
          throw new ErrorException("The buffer to receive the adapter information is too small.");
        }
      }
      long result = IphlpapiMapping.MAPPING.GetAdaptersInfo(adapterInfo, length);
      if (result == 0) {
        Pointer<windows_structs._IP_ADAPTER_INFO> next = adapterInfo;
        while (next != null && !next.isNull()) {
          windows_structs._IP_ADAPTER_INFO info = next.get();
          if (info.AddressLength$get() == MacAddress.MAC_ADDRESS_LENGTH) {
            Array<Byte> byteArray = info.AdapterName$get();
            byte[] adapter = new byte[(int) byteArray.bytesSize()];
            for (int i = 0; i < adapter.length; i++) {
              adapter[i] = byteArray.get(i);
            }
            String adapterName = new String(adapter, StandardCharsets.UTF_8).trim();
            if (source.name().contains("{") && source.name().contains("}")) {
              String sourceName =
                  source
                      .name()
                      .substring(source.name().indexOf('{'), source.name().indexOf('}') + 1);
              if (adapterName.equals(sourceName)) {
                Array<Byte> byteAddress = info.Address$get();
                byte[] address = new byte[MacAddress.MAC_ADDRESS_LENGTH];
                for (int i = 0; i < address.length; i++) {
                  address[i] = (byte) (byteAddress.get(i) & 0xFF);
                }
                scope.close();
                return MacAddress.valueOf(address);
              }
            }
          }
          next = info.Next$get();
        }
      }
      scope.close();
      throw new ErrorException("Error (" + result + ")");
    } else {
      NetworkInterface networkInterface;
      try {
        networkInterface = NetworkInterface.getByName(source.name());
        if (networkInterface != null) {
          byte[] hardwareAddress = networkInterface.getHardwareAddress();
          if (hardwareAddress != null && hardwareAddress.length == MacAddress.MAC_ADDRESS_LENGTH) {
            return MacAddress.valueOf(hardwareAddress);
          }
        }
        throw new ErrorException("Not found.");
      } catch (SocketException e) {
        throw new ErrorException(e.getMessage());
      }
    }
  }

  /**
   * Lookup {@link Inet4Address} from {@link Interface}.
   *
   * @param source {@link Interface}.
   * @return returns {@link Inet4Address}.
   * @throws ErrorException address not found.
   */
  public static Inet4Address lookupInet4Address(Interface source) throws ErrorException {
    Iterator<Address> addressIterator = source.addresses().iterator();
    while (addressIterator.hasNext()) {
      Address next = addressIterator.next();
      if (next.address() != null
          && !next.address().isLoopbackAddress()
          && next.address() instanceof java.net.Inet4Address) {
        Inet4Address inet4Address = Inet4Address.valueOf(next.address().getAddress());
        if (!inet4Address.equals(Inet4Address.ZERO)) {
          return inet4Address;
        }
      }
    }
    throw new ErrorException("Not found.");
  }

  /**
   * Lookup {@link Inet6Address} from {@link Interface}.
   *
   * @param source {@link Interface}.
   * @return returns {@link Inet6Address}.
   * @throws ErrorException address not found.
   */
  public static Inet6Address lookupInet6Address(Interface source) throws ErrorException {
    Iterator<Address> addressIterator = source.addresses().iterator();
    while (addressIterator.hasNext()) {
      Address next = addressIterator.next();
      if (next.address() != null
          && !next.address().isLoopbackAddress()
          && next.address() instanceof java.net.Inet6Address) {
        Inet6Address inet6Address = Inet6Address.valueOf(next.address().getAddress());
        if (!inet6Address.equals(Inet6Address.ZERO)) {
          return inet6Address;
        }
      }
    }
    throw new ErrorException("IPv6 address not found for " + source.name());
  }

  /**
   * Get native pcap library version.
   *
   * @return returns native pcap library version.
   */
  public static String version() {
    synchronized (PcapMapping.LOCK) {
      return Pointer.toString(PcapMapping.MAPPING.pcap_lib_version());
    }
  }

  abstract Pcap open() throws Throwable;
}

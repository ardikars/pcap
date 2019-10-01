/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.NativeTypes;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.util.stream.StreamSupport;
import pcap.api.internal.PcapConstant;
import pcap.api.internal.PcapInterface;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.*;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class Pcaps {

  abstract Pcap open() throws Throwable;

  public static Pcap offline(PcapOffline pcapOffline) throws ErrorException {
    return pcapOffline.open();
  }

  public static Pcap live(PcapLive pcapLive)
      throws InterfaceNotSupportTimestampTypeException, InterfaceNotUpException,
          RadioFrequencyModeNotSupportedException, ActivatedException, PermissionDeniedException,
          NoSuchDeviceException, PromiscuousModePermissionDeniedException, ErrorException,
          TimestampPrecisionNotSupportedException {
    return pcapLive.open();
  }

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

  public static String version() {
    synchronized (PcapConstant.LOCK) {
      return Pointer.toString(PcapConstant.MAPPING.pcap_lib_version());
    }
  }
}

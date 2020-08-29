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
import pcap.api.internal.foreign.mapping.IphlpapiMapping;
import pcap.api.internal.foreign.struct.windows_structs;
import pcap.api.internal.util.Platforms;
import pcap.common.annotation.Inclubating;
import pcap.common.net.MacAddress;
import pcap.spi.Interface;
import pcap.spi.exception.ErrorException;

@Inclubating
public class InterfaceUtils {

  public static <T> T lookupHardwareAddress(Interface source, Class<T> type) throws ErrorException {
    if (type == MacAddress.class) {
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
        try {
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
                    return (T) MacAddress.valueOf(adapter);
                  }
                }
              }
              next = info.Next$get();
            }
          }
          scope.close();
          throw new ErrorException("Error (" + result + ")");
        } catch (IllegalStateException e) {
          throw new ErrorException("Error getting mac address for " + source.name());
        }
      } else {
        NetworkInterface networkInterface;
        try {
          networkInterface = NetworkInterface.getByName(source.name());
          if (networkInterface != null) {
            byte[] hardwareAddress = networkInterface.getHardwareAddress();
            if (hardwareAddress != null
                && hardwareAddress.length == MacAddress.MAC_ADDRESS_LENGTH) {
              return (T) MacAddress.valueOf(hardwareAddress);
            }
          }
          throw new ErrorException("Not found.");
        } catch (SocketException e) {
          throw new ErrorException(e.getMessage());
        }
      }
    } else {
      throw new ErrorException("Unsupported type.");
    }
  }
}

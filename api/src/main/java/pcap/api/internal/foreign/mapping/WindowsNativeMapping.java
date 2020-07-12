package pcap.api.internal.foreign.mapping;

import java.foreign.Libraries;
import java.foreign.annotations.NativeFunction;
import java.foreign.annotations.NativeHeader;
import java.foreign.memory.Pointer;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.struct.windows_structs;

public class WindowsNativeMapping {

  private static final windows_iphlpapi_mapping IPHLPAPI_MAPPING;

  static {
    MethodHandles.Lookup lookup = MethodHandles.lookup();
    IPHLPAPI_MAPPING =
        Libraries.bind(windows_iphlpapi_mapping.class, Libraries.loadLibrary(lookup, "iphlpapi"));
  }

  public static long GetAdaptersInfo(
      Pointer<windows_structs._IP_ADAPTER_INFO> AdapterInfo, Pointer<Long> SizePointer) {
    return IPHLPAPI_MAPPING.GetAdaptersInfo(AdapterInfo, SizePointer);
  }

  @NativeHeader()
  public interface windows_iphlpapi_mapping {

    @NativeFunction("(u64:${IP_ADAPTER_INFO}u64:u64)u64")
    long GetAdaptersInfo(
        Pointer<windows_structs._IP_ADAPTER_INFO> AdapterInfo, Pointer<Long> SizePointer);
  }
}

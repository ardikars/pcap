package pcap.api.internal.foreign.mapping;

import java.foreign.Libraries;
import java.foreign.Scope;
import java.foreign.annotations.NativeFunction;
import java.foreign.annotations.NativeHeader;
import java.foreign.memory.Pointer;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.struct.windows_struct;

public class WindowsNativeMapping {

  public static final Scope IPHLPAPI_SCOPE;
  public static final Scope MALLOC_SCOPE;
  private static final windows_iphlpapi_mapping IPHLPAPI_MAPPING;
  private static final windows_malloc_mapping MALLOC_MAPPING;

  static {
    MethodHandles.Lookup lookup = MethodHandles.lookup();
    IPHLPAPI_MAPPING =
        Libraries.bind(windows_iphlpapi_mapping.class, Libraries.loadLibrary(lookup, "iphlpapi"));
    MALLOC_MAPPING = Libraries.bind(lookup, windows_malloc_mapping.class);
    IPHLPAPI_SCOPE = Libraries.libraryScope(IPHLPAPI_MAPPING);
    MALLOC_SCOPE = Libraries.libraryScope(MALLOC_MAPPING);
  }

  public static long GetAdaptersInfo(
      Pointer<windows_struct._IP_ADAPTER_INFO> AdapterInfo, Pointer<Long> SizePointer) {
    return IPHLPAPI_MAPPING.GetAdaptersInfo(AdapterInfo, SizePointer);
  }

  public static void free(Pointer<Void> memblock) {
    MALLOC_MAPPING.free(memblock);
  }

  @NativeHeader()
  public interface windows_iphlpapi_mapping {

    @NativeFunction("(u64:${IP_ADAPTER_INFO}u64:u64)u64")
    long GetAdaptersInfo(
        Pointer<windows_struct._IP_ADAPTER_INFO> AdapterInfo, Pointer<Long> SizePointer);
  }

  @NativeHeader
  public interface windows_malloc_mapping {

    @NativeFunction("(u64:v)v")
    void free(Pointer<Void> memblock);
  }
}

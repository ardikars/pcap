/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign;

import java.foreign.annotations.NativeFunction;
import java.foreign.annotations.NativeHeader;
import java.foreign.memory.Pointer;
import pcap.api.internal.foreign.struct.windows_structs;

/**
 * iphlpapi mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@NativeHeader
public interface iphlpapi_header {

  @NativeFunction("(u64:${IP_ADAPTER_INFO}u64:u64)u64")
  long GetAdaptersInfo(
      Pointer<windows_structs._IP_ADAPTER_INFO> AdapterInfo, Pointer<Long> SizePointer);
}

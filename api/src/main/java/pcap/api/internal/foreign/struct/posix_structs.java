/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign.struct;

import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Struct;

/**
 * Common structs.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface posix_structs {

  @NativeStruct("${sockaddr}")
  interface sockaddr extends Struct<sockaddr> {}
}

/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign;

import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Struct;

/**
 * Common structs.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class struct_mapping {

  @NativeStruct("${sockaddr}")
  public interface sockaddr extends Struct<sockaddr> {}
}

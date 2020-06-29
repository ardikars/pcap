package pcap.api.internal.foreign;

import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Struct;

public class struct_mapping {

  @NativeStruct("${sockaddr}")
  public interface sockaddr extends Struct<sockaddr> {}
}

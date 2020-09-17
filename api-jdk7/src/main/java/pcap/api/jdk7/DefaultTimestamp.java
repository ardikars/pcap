package pcap.api.jdk7;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import java.util.ArrayList;
import java.util.List;
import pcap.spi.Timestamp;

public class DefaultTimestamp extends StructureReference implements Timestamp {

  static final int TV_SEC_OFFSET;
  static final int TV_USEC_OFFSET;

  static {
    DefaultTimestamp tv = new DefaultTimestamp();
    TV_SEC_OFFSET = tv.fieldOffset("tv_sec");
    TV_USEC_OFFSET = tv.fieldOffset("tv_usec");
  }

  public NativeLong tv_sec;
  public NativeLong tv_usec;

  public DefaultTimestamp() {}

  public DefaultTimestamp(Pointer pointer) {
    super(pointer);
    read();
  }

  @Override
  protected List<String> getFieldOrder() {
    List<String> list = new ArrayList<String>();
    list.add("tv_sec");
    list.add("tv_usec");
    return list;
  }

  @Override
  public long second() {
    return getPointer().getNativeLong(TV_SEC_OFFSET).longValue();
  }

  @Override
  public long microSecond() {
    return getPointer().getNativeLong(TV_USEC_OFFSET).longValue();
  }
}

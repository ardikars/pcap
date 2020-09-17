package pcap.api.jdk7;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.util.ArrayList;
import java.util.List;
import pcap.spi.Statistics;

public class DefaultStatistics extends Structure implements Statistics {

  public static final int PS_RECV_OFFSET;
  public static final int PS_DROP_OFFSET;
  public static final int PS_IFDROP_OFFSET;

  static {
    DefaultStatistics ph = new DefaultStatistics();
    PS_RECV_OFFSET = ph.fieldOffset("ps_recv");
    PS_DROP_OFFSET = ph.fieldOffset("ps_drop");
    PS_IFDROP_OFFSET = ph.fieldOffset("ps_ifdrop");
  }

  public int ps_recv;
  public int ps_drop;
  public int ps_ifdrop;

  public DefaultStatistics() {}

  public DefaultStatistics(Pointer p) {
    super(p);
  }

  @Override
  protected List<String> getFieldOrder() {
    List<String> list = new ArrayList<String>();
    list.add("ps_recv");
    list.add("ps_drop");
    list.add("ps_ifdrop");
    return list;
  }

  @Override
  public int received() {
    return getPointer().getInt(PS_RECV_OFFSET);
  }

  @Override
  public int dropped() {
    return getPointer().getInt(PS_DROP_OFFSET);
  }

  @Override
  public int droppedByInterface() {
    return getPointer().getInt(PS_IFDROP_OFFSET);
  }
}

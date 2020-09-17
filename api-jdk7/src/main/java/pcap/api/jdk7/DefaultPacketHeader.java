package pcap.api.jdk7;

import com.sun.jna.Pointer;
import java.util.ArrayList;
import java.util.List;
import pcap.spi.PacketHeader;

public class DefaultPacketHeader extends StructureReference implements PacketHeader {

  static final int TS_OFFSET;
  static final int CAPLEN_OFFSET;
  static final int LEN_OFFSET;

  static {
    DefaultPacketHeader ph = new DefaultPacketHeader();
    TS_OFFSET = ph.fieldOffset("ts");
    CAPLEN_OFFSET = ph.fieldOffset("caplen");
    LEN_OFFSET = ph.fieldOffset("len");
  }

  public DefaultTimestamp ts;
  public int caplen;
  public int len;

  public DefaultPacketHeader() {
    super();
    this.ts = new DefaultTimestamp();
  }

  public DefaultPacketHeader(Pointer pointer) {
    super(pointer);
    read();
    this.ts = new DefaultTimestamp(pointer.share(TS_OFFSET));
  }

  @Override
  public DefaultTimestamp timestamp() {
    return ts;
  }

  @Override
  public int captureLength() {
    return getPointer().getInt(CAPLEN_OFFSET);
  }

  @Override
  public int length() {
    return getPointer().getInt(LEN_OFFSET);
  }

  @Override
  protected List<String> getFieldOrder() {
    List<String> list = new ArrayList<String>();
    list.add("ts");
    list.add("caplen");
    list.add("len");
    return list;
  }
}

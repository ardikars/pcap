package pcap.jdk7.internal;

import java.util.ArrayList;
import java.util.List;
import pcap.spi.PacketHeader;

public class DefaultPacketHeader extends com.sun.jna.Structure implements PacketHeader {

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
  com.sun.jna.ptr.PointerByReference reference;

  public DefaultPacketHeader() {
    this.reference = new com.sun.jna.ptr.PointerByReference();
  }

  public DefaultPacketHeader(com.sun.jna.Pointer pointer) {
    super(pointer);
    this.reference = new com.sun.jna.ptr.PointerByReference(pointer);
    read();
  }

  void useReferece() {
    if (reference.getValue() != null) {
      useMemory(reference.getValue());
      read();
    }
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

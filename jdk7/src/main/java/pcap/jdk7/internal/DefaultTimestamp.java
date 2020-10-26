package pcap.jdk7.internal;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import pcap.spi.Timestamp;

class DefaultTimestamp implements Timestamp {

  static final int TV_SEC_OFFSET = 0;
  static final int TV_USEC_OFFSET = Native.LONG_SIZE;
  static final int SIZEOF = TV_USEC_OFFSET + Native.LONG_SIZE;

  private com.sun.jna.Pointer pointer;

  DefaultTimestamp() {
    this(Pointer.NULL);
  }

  DefaultTimestamp(com.sun.jna.Pointer pointer) {
    this.pointer = pointer;
  }

  void setPointer(com.sun.jna.Pointer pointer) {
    this.pointer = pointer;
  }

  @Override
  public long second() {
    if (pointer != null) {
      return pointer.getNativeLong(TV_SEC_OFFSET).longValue();
    } else {
      return 0L;
    }
  }

  @Override
  public long microSecond() {
    if (pointer != null) {
      return pointer.getNativeLong(TV_USEC_OFFSET).longValue();
    } else {
      return 0L;
    }
  }
}

/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.jdk7.internal;

import pcap.spi.PacketHeader;

class DefaultPacketHeader implements PacketHeader {

  static final int CAPLEN_OFFSET = DefaultTimestamp.SIZEOF;
  static final int LEN_OFFSET = CAPLEN_OFFSET + 4;
  static final int SIZEOF = LEN_OFFSET + 4;

  private final DefaultTimestamp ts;
  com.sun.jna.Pointer pointer;
  com.sun.jna.ptr.PointerByReference reference;

  DefaultPacketHeader() {
    this.reference = new com.sun.jna.ptr.PointerByReference();
    this.ts = new DefaultTimestamp();
  }

  DefaultPacketHeader(com.sun.jna.Pointer pointer) {
    this.pointer = pointer;
    this.ts = new DefaultTimestamp(pointer);
  }

  void useReference() {
    setPointer(reference.getValue());
  }

  void setPointer(com.sun.jna.Pointer pointer) {
    this.pointer = pointer;
    this.ts.setPointer(pointer);
  }

  @Override
  public DefaultTimestamp timestamp() {
    return ts;
  }

  @Override
  public int captureLength() {
    if (pointer != null) {
      return pointer.getInt(CAPLEN_OFFSET);
    } else {
      return 0;
    }
  }

  @Override
  public int length() {
    if (pointer != null) {
      return pointer.getInt(LEN_OFFSET);
    } else {
      return 0;
    }
  }

  @Override
  public String toString() {
    String format = "[%s] => [second: %d, microSecond: %d, captureLength: %d, length: %d]";
    return String.format(
        format,
        getClass().getSimpleName(),
        timestamp().second(),
        timestamp().microSecond(),
        captureLength(),
        length());
  }
}

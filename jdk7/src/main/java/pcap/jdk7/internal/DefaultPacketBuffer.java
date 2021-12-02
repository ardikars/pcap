/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import pcap.common.logging.Logger;
import pcap.common.logging.LoggerFactory;
import pcap.spi.Packet;
import pcap.spi.PacketBuffer;
import pcap.spi.exception.MemoryAccessException;
import pcap.spi.exception.MemoryLeakException;

class DefaultPacketBuffer implements PacketBuffer {

  private static final Logger LOG = LoggerFactory.getLogger(DefaultPacketBuffer.class);

  private static final boolean LEAK_DETECTION =
      System.getProperty("pcap.leakDetection", "false").equals("true");

  private static final ConcurrentHashMap<Class<?>, Constructor<?>> CACHE =
      new ConcurrentHashMap<Class<?>, Constructor<?>>();

  private static final int BYTE_SIZE = 1;
  private static final int SHORT_SIZE = 2;
  private static final int INT_SIZE = 4;
  private static final int LONG_SIZE = 8;

  private static final boolean BE;

  static {
    com.sun.jna.Native.register(
        DefaultPacketBuffer.class,
        com.sun.jna.NativeLibrary.getInstance(com.sun.jna.Platform.C_LIBRARY_NAME));
    BE = nativeOrderIsBE(ByteOrder.NATIVE);
  }

  protected long capacity;
  protected long writtenBytes = 0L; // for setCharSequence and writeCharSequence
  protected long readerIndex;
  protected long writerIndex;
  protected long markedReaderIndex;
  protected long markedWriterIndex;
  com.sun.jna.Pointer buffer;
  com.sun.jna.ptr.PointerByReference reference;

  private boolean bigEndian = true;

  DefaultPacketBuffer() {
    this.reference = new com.sun.jna.ptr.PointerByReference();
  }

  DefaultPacketBuffer(
      com.sun.jna.Pointer buffer,
      ByteOrder byteOrder,
      long capacity,
      long readerIndex,
      long writerIndex) {
    this.buffer = buffer;
    this.reference = new com.sun.jna.ptr.PointerByReference(buffer);
    this.capacity = capacity;
    this.readerIndex = readerIndex;
    this.writerIndex = writerIndex;
    this.markedReaderIndex = 0L;
    this.markedWriterIndex = 0L;
    bigEndian = byteOrder == ByteOrder.BIG_ENDIAN;
  }

  static boolean nativeOrderIsBE(ByteOrder bo) {
    return bo == ByteOrder.BIG_ENDIAN;
  }

  static native com.sun.jna.Pointer memcpy(
      com.sun.jna.Pointer dst, com.sun.jna.Pointer src, long n);

  static native int memcmp(com.sun.jna.Pointer buf1, com.sun.jna.Pointer buf2, long size);

  static <T extends Packet.Abstract> T checkCastThrowable(Class<?> type, Throwable e) {
    if (e.getCause() instanceof IllegalArgumentException) {
      throw (IllegalArgumentException) e.getCause();
    } else if (e instanceof NoSuchMethodException) {
      throw new IllegalArgumentException(
          String.format(
              "Add constructor: public %s(%s) to %s.",
              type.getSimpleName(), PacketBuffer.class.getName(), type.getName()));
    } else if (e instanceof InvocationTargetException) {
      throw (RuntimeException) e.getCause();
    } else if (e instanceof InstantiationException) {
      throw new IllegalArgumentException(
          String.format("A class must be extends %s.", Packet.Abstract.class.getName()));
    }
    return null;
  }

  static int pickPos(int top, int pos) {
    return BE ? top - pos : pos;
  }

  static byte pick(byte le, byte be) {
    return BE ? be : le;
  }

  static short pick(short le, short be) {
    return BE ? be : le;
  }

  static int pick(int le, int be) {
    return BE ? be : le;
  }

  void useReference(DefaultPacketHeader header) {
    this.buffer = reference.getValue();
    this.capacity = header.captureLength();
    this.readerIndex = 0;
    this.writerIndex = header.captureLength();
    this.markedReaderIndex = 0;
    this.markedWriterIndex = 0;
  }

  @Override
  public long capacity() {
    return capacity;
  }

  @Override
  public PacketBuffer capacity(long newCapacity) {
    if (newCapacity <= 0) {
      throw new IllegalArgumentException(
          String.format(
              "newCapacity: %d (expected: newCapacity(%d) > 0)", newCapacity, newCapacity));
    }
    if (buffer == null) {
      FinalizablePacketBuffer finalizablePacketBuffer = PacketBufferManager.allocate(newCapacity);
      finalizablePacketBuffer.reference = this.reference;
      finalizablePacketBuffer.reference.setValue(finalizablePacketBuffer.buffer);
      return finalizablePacketBuffer;
    } else {
      if (newCapacity <= capacity) {
        this.capacity = newCapacity;
        this.readerIndex = readerIndex > newCapacity ? newCapacity : readerIndex;
        this.writerIndex = writerIndex > newCapacity ? newCapacity : writerIndex;
        this.markedReaderIndex = 0L;
        this.markedWriterIndex = 0L;
        return this;
      } else {
        FinalizablePacketBuffer finalizableBuffer = PacketBufferManager.allocate(newCapacity);
        memcpy(finalizableBuffer.buffer, buffer, capacity);
        release();
        finalizableBuffer.reference = reference;
        finalizableBuffer.reference.setValue(finalizableBuffer.buffer);
        finalizableBuffer.readerIndex = readerIndex;
        finalizableBuffer.writerIndex = writerIndex;
        finalizableBuffer.markedReaderIndex = 0L;
        finalizableBuffer.markedWriterIndex = 0L;
        return finalizableBuffer;
      }
    }
  }

  @Override
  public long readerIndex() {
    return readerIndex;
  }

  @Override
  public PacketBuffer readerIndex(long readerIndex) {
    if (readerIndex < 0 || readerIndex > writerIndex) {
      throw new IndexOutOfBoundsException(
          String.format(
              "readerIndex: %d (expected: 0 <= readerIndex <= writerIndex(%d))",
              readerIndex, writerIndex));
    }
    this.readerIndex = readerIndex;
    return this;
  }

  @Override
  public long writerIndex() {
    return writerIndex;
  }

  @Override
  public PacketBuffer writerIndex(long writerIndex) {
    if (writerIndex < readerIndex || writerIndex > capacity) {
      throw new IndexOutOfBoundsException(
          String.format(
              "writerIndex: %d (expected: readerIndex(%d) <= writerIndex(%d) <= capacity(%d))",
              writerIndex, readerIndex, writerIndex, capacity));
    }
    this.writerIndex = writerIndex;
    return this;
  }

  @Override
  public PacketBuffer setIndex(long readerIndex, long writerIndex) {
    if (readerIndex < 0 || readerIndex > writerIndex || writerIndex > capacity) {
      throw new IndexOutOfBoundsException(
          String.format(
              "readerIndex: %d, writerIndex: %d (expected: 0 <= readerIndex <= writerIndex <= capacity(%d))",
              readerIndex, writerIndex, capacity));
    }
    this.readerIndex = readerIndex;
    this.writerIndex = writerIndex;
    return this;
  }

  @Override
  public long readableBytes() {
    return writerIndex - readerIndex;
  }

  @Override
  public long writableBytes() {
    return capacity - writerIndex;
  }

  @Override
  public boolean isReadable() {
    return writerIndex > readerIndex;
  }

  @Override
  public boolean isReadable(long numBytes) {
    return numBytes > 0 && writerIndex - readerIndex >= numBytes;
  }

  @Override
  public boolean isWritable() {
    return capacity > writerIndex;
  }

  @Override
  public boolean isWritable(long numBytes) {
    return numBytes > 0 && capacity - writerIndex >= numBytes;
  }

  @Override
  public PacketBuffer clear() {
    writerIndex = readerIndex = 0;
    return this;
  }

  @Override
  public PacketBuffer markReaderIndex() {
    markedReaderIndex = readerIndex;
    return this;
  }

  @Override
  public PacketBuffer resetReaderIndex() {
    readerIndex = markedReaderIndex;
    return this;
  }

  @Override
  public PacketBuffer markWriterIndex() {
    markedWriterIndex = writerIndex;
    return this;
  }

  @Override
  public PacketBuffer resetWriterIndex() {
    writerIndex = markedWriterIndex;
    return this;
  }

  @Override
  public PacketBuffer ensureWritable(long minWritableBytes) {
    if (minWritableBytes < 0) {
      throw new IllegalArgumentException(
          String.format("minWritableBytes: %d (expected: >= 0)", minWritableBytes));
    }
    checkWritableBytes(minWritableBytes);
    return this;
  }

  @Override
  public boolean getBoolean(long index) {
    return getByte(index) != 0;
  }

  @Override
  public short getUnsignedByte(long index) {
    return (short) (getByte(index) & 0xFF);
  }

  @Override
  public short getShortRE(long index) {
    return Short.reverseBytes(getShort(index));
  }

  @Override
  public int getUnsignedShort(long index) {
    return getShort(index) & 0xFFFF;
  }

  @Override
  public int getUnsignedShortRE(long index) {
    return Short.reverseBytes((short) getUnsignedShort(index)) & 0xFFFF;
  }

  @Override
  public int getIntRE(long index) {
    return Integer.reverseBytes(getInt(index));
  }

  @Override
  public long getUnsignedInt(long index) {
    return getInt(index) & 0xFFFFFFFFL;
  }

  @Override
  public long getUnsignedIntRE(long index) {
    return Integer.reverseBytes((int) getUnsignedInt(index)) & 0xFFFFFFFFL;
  }

  @Override
  public long getLongRE(long index) {
    return Long.reverseBytes(getLong(index));
  }

  @Override
  public float getFloat(long index) {
    return Float.intBitsToFloat(getInt(index));
  }

  @Override
  public float getFloatRE(long index) {
    return Float.intBitsToFloat(getIntRE(index));
  }

  @Override
  public double getDouble(long index) {
    return Double.longBitsToDouble(getLong(index));
  }

  @Override
  public double getDoubleRE(long index) {
    return Double.longBitsToDouble(getLongRE(index));
  }

  @Override
  public PacketBuffer getBytes(long index, PacketBuffer dst) {
    return getBytes(index, dst, dst.writableBytes());
  }

  @Override
  public PacketBuffer getBytes(long index, PacketBuffer dst, long length) {
    getBytes(index, dst, dst.writerIndex(), length);
    dst.writerIndex(dst.writerIndex() + length);
    return this;
  }

  @Override
  public PacketBuffer getBytes(long index, byte[] dst) {
    return getBytes(index, dst, 0, dst.length);
  }

  @Override
  public PacketBuffer setBoolean(long index, boolean value) {
    return setByte(index, value ? 1 : 0);
  }

  @Override
  public PacketBuffer setShortRE(long index, int value) {
    return setShort(index, Short.reverseBytes((short) (value & 0xFFFF)));
  }

  @Override
  public PacketBuffer setIntRE(long index, int value) {
    return setInt(index, Integer.reverseBytes(value));
  }

  @Override
  public PacketBuffer setLongRE(long index, long value) {
    return setLong(index, Long.reverseBytes(value));
  }

  @Override
  public PacketBuffer setFloat(long index, float value) {
    return setInt(index, Float.floatToRawIntBits(value));
  }

  @Override
  public PacketBuffer setFloatRE(long index, float value) {
    return setIntRE(index, Float.floatToRawIntBits(value));
  }

  @Override
  public PacketBuffer setDouble(long index, double value) {
    return setLong(index, Double.doubleToRawLongBits(value));
  }

  @Override
  public PacketBuffer setDoubleRE(long index, double value) {
    return setLongRE(index, Double.doubleToRawLongBits(value));
  }

  @Override
  public PacketBuffer setBytes(long index, PacketBuffer src) {
    return setBytes(index, src, src.readableBytes());
  }

  @Override
  public PacketBuffer setBytes(long index, PacketBuffer src, long length) {
    checkIndex(index, length);
    if (src == null) {
      throw new IllegalArgumentException("src must be not null.");
    }
    if (length > src.readableBytes()) {
      throw new IndexOutOfBoundsException(
          String.format(
              "length(%d) exceeds src.readableBytes(%d) where src is: %s",
              length, src.readableBytes(), src));
    }

    setBytes(index, src, src.readerIndex(), length);
    src.readerIndex(src.readerIndex() + length);
    return this;
  }

  @Override
  public PacketBuffer setBytes(long index, byte[] src) {
    return setBytes(index, src, 0, src.length);
  }

  @Override
  public PacketBuffer setCharSequence(long index, CharSequence seq, Charset charset) {
    this.writtenBytes = Utils.setCharSequence(this, index, seq, charset);
    return this;
  }

  @Override
  public boolean readBoolean() {
    return readByte() != 0;
  }

  @Override
  public byte readByte() {
    checkReadableBytes(1);
    long i = readerIndex;
    byte b = getByte(i);
    readerIndex = i + 1;
    return b;
  }

  @Override
  public short readUnsignedByte() {
    return (short) (readByte() & 0xFF);
  }

  @Override
  public short readShort() {
    checkReadableBytes(2);
    short v = getShort(readerIndex);
    readerIndex += 2;
    return v;
  }

  @Override
  public short readShortRE() {
    checkReadableBytes(2);
    short v = getShortRE(readerIndex);
    readerIndex += 2;
    return v;
  }

  @Override
  public int readUnsignedShort() {
    return readShort() & 0xFFFF;
  }

  @Override
  public int readUnsignedShortRE() {
    return readShortRE() & 0xFFFF;
  }

  @Override
  public int readInt() {
    checkReadableBytes(4);
    int v = getInt(readerIndex);
    readerIndex += 4;
    return v;
  }

  @Override
  public int readIntRE() {
    checkReadableBytes(4);
    int v = getIntRE(readerIndex);
    readerIndex += 4;
    return v;
  }

  @Override
  public long readUnsignedInt() {
    return readInt() & 0xFFFFFFFFL;
  }

  @Override
  public long readUnsignedIntRE() {
    return readIntRE() & 0xFFFFFFFFL;
  }

  @Override
  public float readFloat() {
    return Float.intBitsToFloat(readInt());
  }

  @Override
  public float readFloatRE() {
    return Float.intBitsToFloat(readIntRE());
  }

  @Override
  public double readDouble() {
    return Double.longBitsToDouble(readLong());
  }

  @Override
  public double readDoubleRE() {
    return Double.longBitsToDouble(readLongRE());
  }

  @Override
  public long readLong() {
    checkReadableBytes(8);
    long v = getLong(readerIndex);
    readerIndex += 8;
    return v;
  }

  @Override
  public long readLongRE() {
    checkReadableBytes(8);
    long v = getLongRE(readerIndex);
    readerIndex += 8;
    return v;
  }

  @Override
  public PacketBuffer readBytes(PacketBuffer dst) {
    return readBytes(dst, dst.writableBytes());
  }

  @Override
  public PacketBuffer readBytes(PacketBuffer dst, long length) {
    return readBytes(dst, 0, length);
  }

  @Override
  public PacketBuffer readBytes(PacketBuffer dst, long dstIndex, long length) {
    checkReadableBytes(length);
    getBytes(readerIndex, dst, dstIndex, length);
    readerIndex += length;
    return this;
  }

  @Override
  public PacketBuffer readBytes(byte[] dst) {
    return readBytes(dst, 0, dst.length);
  }

  @Override
  public PacketBuffer readBytes(byte[] dst, long dstIndex, long length) {
    checkReadableBytes(length);
    getBytes(readerIndex, dst, dstIndex, length);
    readerIndex += length;
    return this;
  }

  @Override
  public PacketBuffer skipBytes(long length) {
    checkReadableBytes(length);
    readerIndex += length;
    return this;
  }

  @Override
  public CharSequence readCharSequence(long length, Charset charset) {
    CharSequence sequence = getCharSequence(readerIndex, length, charset);
    readerIndex += length;
    return sequence;
  }

  @Override
  public PacketBuffer writeBoolean(boolean value) {
    return writeByte(value ? 1 : 0);
  }

  @Override
  public PacketBuffer writeByte(int value) {
    checkWritableBytes(1);
    return setByte(writerIndex++, value);
  }

  @Override
  public PacketBuffer writeShort(int value) {
    checkWritableBytes(2);
    setShort(writerIndex, value);
    writerIndex += 2;
    return this;
  }

  @Override
  public PacketBuffer writeShortRE(int value) {
    checkWritableBytes(2);
    setShortRE(writerIndex, value);
    writerIndex += 2;
    return this;
  }

  @Override
  public PacketBuffer writeInt(int value) {
    checkWritableBytes(4);
    setInt(writerIndex, value);
    writerIndex += 4;
    return this;
  }

  @Override
  public PacketBuffer writeIntRE(int value) {
    checkWritableBytes(4);
    setIntRE(writerIndex, value);
    writerIndex += 4;
    return this;
  }

  @Override
  public PacketBuffer writeLong(long value) {
    checkWritableBytes(8);
    setLong(writerIndex, value);
    writerIndex += 8;
    return this;
  }

  @Override
  public PacketBuffer writeLongRE(long value) {
    checkWritableBytes(8);
    setLongRE(writerIndex, value);
    writerIndex += 8;
    return this;
  }

  @Override
  public PacketBuffer writeFloat(float value) {
    return writeInt(Float.floatToRawIntBits(value));
  }

  @Override
  public PacketBuffer writeFloatRE(float value) {
    return writeIntRE(Float.floatToRawIntBits(value));
  }

  @Override
  public PacketBuffer writeDoubleRE(double value) {
    return writeLongRE(Double.doubleToRawLongBits(value));
  }

  @Override
  public PacketBuffer writeDouble(double value) {
    return writeLong(Double.doubleToRawLongBits(value));
  }

  @Override
  public PacketBuffer writeBytes(PacketBuffer src) {
    return writeBytes(src, src.readableBytes());
  }

  @Override
  public PacketBuffer writeBytes(PacketBuffer src, long length) {
    return writeBytes(src, 0, length);
  }

  @Override
  public PacketBuffer writeBytes(PacketBuffer src, long srcIndex, long length) {
    ensureWritable(length);
    setBytes(writerIndex, src, srcIndex, length);
    writerIndex += length;
    return this;
  }

  @Override
  public PacketBuffer writeBytes(byte[] src) {
    return writeBytes(src, 0, src.length);
  }

  @Override
  public PacketBuffer writeBytes(byte[] src, long srcIndex, long length) {
    ensureWritable(length);
    setBytes(writerIndex, src, srcIndex, length);
    writerIndex += length;
    return this;
  }

  @Override
  public PacketBuffer writeCharSequence(CharSequence sequence, Charset charset) {
    setCharSequence(writerIndex, sequence, charset);
    writerIndex += writtenBytes;
    return this;
  }

  @Override
  public ByteOrder byteOrder() {
    return bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
  }

  @Override
  public PacketBuffer copy() {
    return copy(0, capacity);
  }

  @Override
  public PacketBuffer slice() {
    return slice(readerIndex, readableBytes());
  }

  private void checkWritableBytes(long minWritableBytes) {
    if (minWritableBytes > capacity - writerIndex) {
      throw new IndexOutOfBoundsException(
          String.format(
              "writerIndex(%d) + minWritableBytes(%d) exceeds capacity(%d): %s",
              writerIndex, minWritableBytes, capacity, this));
    }
  }

  private void checkReadableBytes(long minimumReadableBytes) {
    if (minimumReadableBytes < 0) {
      throw new IllegalArgumentException(
          String.format("minimumReadableBytes: %d (expected: >= 0)", minimumReadableBytes));
    }
    if (readerIndex > writerIndex - minimumReadableBytes) {
      throw new IndexOutOfBoundsException(
          String.format(
              "readerIndex(%d) + length(%d) exceeds writerIndex(%d): %s",
              readerIndex, minimumReadableBytes, writerIndex, this));
    }
  }

  void checkIndex(long index, long fieldLength) {
    if (isOutOfBounds(index, fieldLength, capacity)) {
      throw new IndexOutOfBoundsException(
          String.format(
              "index: %d, length: %d (expected: range(0, %d))", index, fieldLength, capacity));
    }
  }

  boolean isOutOfBounds(long index, long length, long capacity) {
    return (index | length | (index + length) | (capacity - (index + length))) < 0;
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    DefaultPacketBuffer that = (DefaultPacketBuffer) o;
    if (!isReadable() || !that.isReadable()) {
      return false;
    }
    if (readableBytes() != that.readableBytes()) {
      return false;
    }
    return 0
        == memcmp(
            buffer.share(readerIndex()), that.buffer.share(that.readerIndex()), readableBytes());
  }

  @Override
  public int hashCode() {
    if (!isReadable()) {
      return 0;
    }
    long hcLength = readerIndex + readableBytes();
    int result = 1;
    for (long i = readerIndex; i < hcLength; i++) {
      result = 31 * result + buffer.getByte(i);
    }
    return result;
  }

  @Override
  public String toString() {
    String format =
        "[%s] => [address: %s, capacity: %d, readerIndex: %d, writerIndex: %d, markedReaderIndex: %d, markedWriterIndex: %d]";
    return String.format(
        format,
        getClass().getSimpleName(),
        Pointer.nativeValue(buffer),
        capacity,
        readerIndex,
        writerIndex,
        markedReaderIndex,
        markedWriterIndex);
  }

  /** Implementation */
  @Override
  public byte getByte(long index) {
    // check buffer overflow
    checkIndex(index, BYTE_SIZE);
    return buffer.getByte(index);
  }

  @Override
  public short getShort(long index) {
    // check buffer overflow
    checkIndex(index, SHORT_SIZE);
    short value;
    long offset = Pointer.nativeValue(buffer) + index;
    if ((offset & 1) == 0) {
      value = buffer.getShort(index);
    } else {
      value =
          (short)
              (((buffer.getByte(index) & 0xFF) << pickPos(8, 0))
                  | ((buffer.getByte(index + 1) & 0xFF) << pickPos(8, 8)));
    }
    return bigEndian == BE ? value : Short.reverseBytes(value);
  }

  @Override
  public int getInt(long index) {
    // check buffer overflow
    checkIndex(index, INT_SIZE);
    int value;
    long offset = Pointer.nativeValue(buffer) + index;
    if ((offset & 3) == 0) {
      value = buffer.getInt(index);
    } else if ((offset & 1) == 0) {
      value =
          (buffer.getShort(index) & 0xFFFF) << pickPos(16, 0)
              | (buffer.getShort(index + 2) & 0xFFFF) << pickPos(16, 16);
    } else {
      value =
          ((buffer.getByte(index) & 0xFF) << pickPos(24, 0)
              | (buffer.getByte(index + 1) & 0xFF) << pickPos(24, 8)
              | (buffer.getByte(index + 2) & 0xFF) << pickPos(24, 16)
              | (buffer.getByte(index + 3) & 0xFF) << pickPos(24, 24));
    }
    return bigEndian == BE ? value : Integer.reverseBytes(value);
  }

  @Override
  public long getLong(long index) {
    // check buffer overflow
    checkIndex(index, LONG_SIZE);
    long value;
    long offset = Pointer.nativeValue(buffer) + index;
    if ((offset & 7) == 0) {
      value = buffer.getLong(index);
    } else if ((offset & 3) == 0) {
      value =
          ((buffer.getInt(index) & 0xFFFFFFFFL) << pickPos(32, 0))
              | ((buffer.getInt(index + 4) & 0xFFFFFFFFL) << pickPos(32, 32));
    } else if ((offset & 1) == 0) {
      value =
          (((buffer.getShort(index) & 0xFFFFL) << pickPos(48, 0))
              | ((buffer.getShort(index + 2) & 0xFFFFL) << pickPos(48, 16))
              | ((buffer.getShort(index + 4) & 0xFFFFL) << pickPos(48, 32))
              | ((buffer.getShort(index + 6) & 0xFFFFL) << pickPos(48, 48)));
    } else {
      value =
          (((buffer.getByte(index) & 0xFFL) << pickPos(56, 0))
              | ((buffer.getByte(index + 1) & 0xFFL) << pickPos(56, 8))
              | ((buffer.getByte(index + 2) & 0xFFL) << pickPos(56, 16))
              | ((buffer.getByte(index + 3) & 0xFFL) << pickPos(56, 24))
              | ((buffer.getByte(index + 4) & 0xFFL) << pickPos(56, 32))
              | ((buffer.getByte(index + 5) & 0xFFL) << pickPos(56, 40))
              | ((buffer.getByte(index + 6) & 0xFFL) << pickPos(56, 48))
              | ((buffer.getByte(index + 7) & 0xFFL) << pickPos(56, 56)));
    }
    return bigEndian == BE ? value : Long.reverseBytes(value);
  }

  @Override
  public PacketBuffer getBytes(long index, PacketBuffer dst, long dstIndex, long length) {
    // check buffer overflow
    checkIndex(index, length);
    if (isOutOfBounds(dstIndex, length, dst.capacity())) {
      throw new IndexOutOfBoundsException(
          String.format(
              "dstIdx: %d, length: %d (expected: dstIdx(%d) <= length(%d)))",
              dstIndex, length, dstIndex, length));
    }
    com.sun.jna.Pointer dstPtr = ((DefaultPacketBuffer) dst).buffer.share(dstIndex, length);
    memcpy(dstPtr, buffer.share(index, length), length);
    return this;
  }

  @Override
  public PacketBuffer getBytes(long index, byte[] dst, long dstIndex, long length) {
    // check buffer overflow
    checkIndex(index, length);
    if (isOutOfBounds(dstIndex, length, dst.length)) {
      throw new IndexOutOfBoundsException(
          String.format(
              "dstIdx: %d, length: %d (expected: dstIdx(%d) <= length(%d)))",
              dstIndex, length, dstIndex, length));
    }
    buffer.read(index, dst, (int) dstIndex, (int) length);
    return this;
  }

  @Override
  public CharSequence getCharSequence(long index, long length, Charset charset) {
    byte[] bytes = new byte[(int) length & 0x7FFFFFFF];
    getBytes(index, bytes);
    return new String(bytes, java.nio.charset.Charset.forName(charset.name()));
  }

  @Override
  public PacketBuffer setByte(long index, int value) {
    // check buffer overflow
    checkIndex(index, BYTE_SIZE);
    buffer.setByte(index, (byte) value);
    return this;
  }

  @Override
  public PacketBuffer setShort(long index, int value) {
    // check buffer overflow
    checkIndex(index, SHORT_SIZE);
    short x = bigEndian == BE ? (short) value : Short.reverseBytes((short) value);
    long offset = Pointer.nativeValue(buffer) + index;
    if ((offset & 1) == 0) {
      buffer.setShort(index, x);
    } else {
      buffer.setByte(index, pick((byte) x, (byte) (x >>> 8)));
      buffer.setByte(index + 1, pick((byte) (x >>> 8), (byte) x));
    }
    return this;
  }

  @Override
  public PacketBuffer setInt(long index, int value) {
    // check buffer overflow
    checkIndex(index, INT_SIZE);
    int x = bigEndian == BE ? value : Integer.reverseBytes(value);
    long offset = Pointer.nativeValue(buffer) + index;
    if ((offset & 3) == 0) {
      buffer.setInt(index, x);
    } else if ((offset & 1) == 0) {
      buffer.setShort(index, pick((short) x, (short) (x >>> 16)));
      buffer.setShort(index + 2, pick((short) (x >>> 16), (short) x));
    } else {
      buffer.setByte(index, pick((byte) x, (byte) (x >>> 24)));
      buffer.setByte(index + 1, pick((byte) (x >>> 8), (byte) (x >>> 16)));
      buffer.setByte(index + 2, pick((byte) (x >>> 16), (byte) (x >>> 8)));
      buffer.setByte(index + 3, pick((byte) (x >>> 24), (byte) x));
    }
    return this;
  }

  @Override
  public PacketBuffer setLong(long index, long value) {
    // check buffer overflow
    checkIndex(index, LONG_SIZE);
    long x = bigEndian == BE ? value : Long.reverseBytes(value);
    long offset = Pointer.nativeValue(buffer) + index;
    if ((offset & 7) == 0) {
      buffer.setLong(index, x);
    } else if ((offset & 3) == 0) {
      buffer.setInt(index, pick((int) (x), (int) (x >>> 32)));
      buffer.setInt(index + 4, pick((int) (x >>> 32), (int) (x)));
    } else if ((offset & 1) == 0) {
      buffer.setShort(index, pick((short) (x), (short) (x >>> 48)));
      buffer.setShort(index + 2, pick((short) (x >>> 16), (short) (x >>> 32)));
      buffer.setShort(index + 4, pick((short) (x >>> 32), (short) (x >>> 16)));
      buffer.setShort(index + 6, pick((short) (x >>> 48), (short) (x)));
    } else {
      buffer.setByte(index, pick((byte) x, (byte) (x >>> 56)));
      buffer.setByte(index + 1, pick((byte) (x >>> 8), (byte) (x >>> 48)));
      buffer.setByte(index + 2, pick((byte) (x >>> 16), (byte) (x >>> 40)));
      buffer.setByte(index + 3, pick((byte) (x >>> 24), (byte) (x >>> 32)));
      buffer.setByte(index + 4, pick((byte) (x >>> 32), (byte) (x >>> 24)));
      buffer.setByte(index + 5, pick((byte) (x >>> 40), (byte) (x >>> 16)));
      buffer.setByte(index + 6, pick((byte) (x >>> 48), (byte) (x >>> 8)));
      buffer.setByte(index + 7, pick((byte) (x >>> 56), (byte) x));
    }
    return this;
  }

  @Override
  public PacketBuffer setBytes(long index, PacketBuffer src, long srcIndex, long length) {
    // check buffer overflow
    checkIndex(index, length);
    if (isOutOfBounds(srcIndex, length, src.capacity())) {
      throw new IndexOutOfBoundsException(
          String.format(
              "srcIdx: %d, length: %d (expected: srcIdx(%d) <= length(%d)))",
              srcIndex, length, srcIndex, length));
    }
    com.sun.jna.Pointer srcPtr = ((DefaultPacketBuffer) src).buffer.share(srcIndex, length);
    memcpy(buffer.share(index, length), srcPtr, length);
    return this;
  }

  @Override
  public PacketBuffer setBytes(long index, byte[] src, long srcIndex, long length) {
    // check buffer overflow
    checkIndex(index, length);
    if (isOutOfBounds(srcIndex, length, src.length)) {
      throw new IndexOutOfBoundsException(
          String.format(
              "srcIdx: %d, length: %d (expected: srcIdx(%d) <= length(%d)))",
              srcIndex, length, srcIndex, length));
    }
    buffer.write(index, src, (int) srcIndex, (int) length);
    return this;
  }

  @Override
  public PacketBuffer copy(long index, long length) {
    // check buffer overflow
    checkIndex(index, length);
    FinalizablePacketBuffer newBuf = PacketBufferManager.allocate(length);
    memcpy(newBuf.buffer, buffer.share(index, length), length);
    return newBuf;
  }

  @Override
  public PacketBuffer slice(long index, long length) {
    // check buffer overflow
    checkIndex(index, length);
    return new Sliced(this, index, length);
  }

  @Override
  public PacketBuffer duplicate() {
    return new DefaultPacketBuffer(buffer, byteOrder(), capacity, readerIndex, writerIndex);
  }

  @Override
  public PacketBuffer byteOrder(ByteOrder byteOrder) {
    bigEndian = byteOrder == ByteOrder.BIG_ENDIAN;
    return this;
  }

  @Override
  public long memoryAddress() throws IllegalAccessException {
    return getMemoryAddress(NativeMappings.RESTRICTED_LEVEL);
  }

  long getMemoryAddress(int restrictedLevel) throws IllegalAccessException {
    if (restrictedLevel > 0) {
      if (restrictedLevel > 1) {
        LOG.warn("Calling restricted method PacketBuffer#memoryAddress().");
      }
      long address = Pointer.nativeValue(buffer);
      if (address == 0L) {
        throw new IllegalStateException("Packet buffer already closed.");
      }
      return address;
    } else {
      throw new IllegalAccessException(NativeMappings.RESTRICTED_MESSAGE);
    }
  }

  @Override
  public boolean release() {
    return false;
  }

  @Override
  public void close() throws Exception {
    if (!release()) {
      throw new IllegalStateException(String.format("Can't release the buffer: %s.", getClass()));
    }
  }

  @Override
  public <T extends Packet.Abstract> T cast(Class<T> type) {
    try {
      Constructor<?> constructor = CACHE.get(type);
      if (constructor == null) {
        constructor = type.getDeclaredConstructor(PacketBuffer.class);
        constructor.setAccessible(true);
        CACHE.put(type, constructor);
      }
      return (T) constructor.newInstance(this);
    } catch (Exception e) {
      return checkCastThrowable(type, e);
    }
  }

  static final class Sliced extends DefaultPacketBuffer implements PacketBuffer.Sliced {

    private final DefaultPacketBuffer prev;

    Sliced(DefaultPacketBuffer prev, long index, long length) {
      super(
          prev.buffer.share(index),
          prev.byteOrder(),
          length,
          prev.readerIndex - index < 0 ? 0 : prev.readerIndex - index,
          prev.writerIndex - index < 0 ? 0 : prev.writerIndex - index);
      this.prev = prev;
    }

    @Override
    public DefaultPacketBuffer unSlice() {
      return prev;
    }

    @Override
    public boolean release() {
      return prev.release();
    }
  }

  static final class FinalizablePacketBuffer extends DefaultPacketBuffer {

    PacketBufferReference phantomReference;

    public FinalizablePacketBuffer(
        Pointer buffer, ByteOrder byteOrder, long capacity, long readerIndex, long writerIndex) {
      super(buffer, byteOrder, capacity, readerIndex, writerIndex);
    }

    @Override
    public boolean release() {
      if (com.sun.jna.Pointer.nativeValue(buffer) > 0 && phantomReference.address > 0) {
        Native.free(phantomReference.address);
        phantomReference.address = 0L;
        com.sun.jna.Pointer.nativeValue(buffer, 0L);
        return true;
      } else {
        return false;
      }
    }

    @Override
    void checkIndex(long index, long fieldLength) {
      if (phantomReference.address == 0L) {
        throw new MemoryAccessException("Accessing closed buffer is prohibited.");
      }
      super.checkIndex(index, fieldLength);
    }
  }

  static final class PacketBufferReference extends PhantomReference<FinalizablePacketBuffer> {

    long address;
    StackTraceElement[] stackTraceElements;

    public PacketBufferReference(
        long rawAddr, FinalizablePacketBuffer referent, ReferenceQueue<FinalizablePacketBuffer> q) {
      super(referent, q);
      this.address = rawAddr;
      referent.phantomReference = this;
      fillStackTrace(LEAK_DETECTION);
    }

    void fillStackTrace(boolean enabled) {
      if (enabled) {
        stackTraceElements = Thread.currentThread().getStackTrace();
      }
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      PacketBufferReference that = (PacketBufferReference) o;
      return Objects.equals(hashCode(), that.hashCode());
    }

    @Override
    public int hashCode() {
      return Objects.hashCode(address);
    }
  }

  static final class PacketBufferManager {

    static final Set<Reference<FinalizablePacketBuffer>> REFS =
        Collections.synchronizedSet(new HashSet<Reference<FinalizablePacketBuffer>>());
    static final ReferenceQueue<FinalizablePacketBuffer> RQ =
        new ReferenceQueue<FinalizablePacketBuffer>();

    private PacketBufferManager() {}

    static FinalizablePacketBuffer allocate(long capacity) {
      long address = Native.malloc(capacity);
      FinalizablePacketBuffer buffer =
          new FinalizablePacketBuffer(new Pointer(address), ByteOrder.BIG_ENDIAN, capacity, 0L, 0L);
      PacketBufferReference bufRef = new PacketBufferReference(address, buffer, RQ);
      REFS.add(bufRef);

      // cleanup native memory wrapped in garbage collected object.
      PacketBufferReference ref;
      while ((ref = (PacketBufferReference) RQ.poll()) != null) {
        checkLeak(ref, LEAK_DETECTION);
        REFS.remove(ref);
      }
      return buffer;
    }

    static void checkLeak(PacketBufferReference ref, boolean enabled) {
      if (ref.address != 0L) {
        Native.free(ref.address); // force deallocate memory and set address to '0'.
        ref.address = 0L;
        if (enabled) {
          StringBuilder stackTraceBuilder = new StringBuilder();
          for (int i = ref.stackTraceElements.length - 1; i >= 0; i--) {
            stackTraceBuilder.append(
                String.format("\t[%s]%n", ref.stackTraceElements[i].toString()));
          }
          throw new MemoryLeakException(
              String.format(
                  "PacketBuffer.release() was not called before it's garbage collected.%n\tCreated at:%n%s",
                  stackTraceBuilder));
        }
      }
    }
  }
}

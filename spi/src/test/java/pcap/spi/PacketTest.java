/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** */
@RunWith(JUnitPlatform.class)
class PacketTest {

  @Test
  void newConstract() {
    BadBuffer badBuffer = new BadBuffer(14);
    BadPacket badPacket = new BadPacket(badBuffer);
    Assertions.assertNotNull(badPacket);
    Assertions.assertNotNull(badPacket.buffer());
    Assertions.assertEquals(14, badPacket.size());
    Assertions.assertThrows(
        IllegalArgumentException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            BadBuffer badBuffer1 = new BadBuffer(10);
            new BadPacket(badBuffer1);
          }
        });
  }

  static final class BadPacket extends Packet.Abstract {

    public BadPacket(PacketBuffer buffer) {
      super(buffer);
    }

    @Override
    protected int size() {
      return 14;
    }
  }

  static final class BadBuffer implements PacketBuffer {

    private final long readbleBytes;

    public BadBuffer(long readbleBytes) {
      this.readbleBytes = readbleBytes;
    }

    @Override
    public long capacity() {
      return 0;
    }

    @Override
    public PacketBuffer capacity(long newCapacity) {
      return null;
    }

    @Override
    public long readerIndex() {
      return 0;
    }

    @Override
    public PacketBuffer readerIndex(long readerIndex) {
      return null;
    }

    @Override
    public long writerIndex() {
      return 0;
    }

    @Override
    public PacketBuffer writerIndex(long writerIndex) {
      return null;
    }

    @Override
    public PacketBuffer setIndex(long readerIndex, long writerIndex) {
      return null;
    }

    @Override
    public long readableBytes() {
      return readbleBytes;
    }

    @Override
    public long writableBytes() {
      return 0;
    }

    @Override
    public boolean isReadable() {
      return false;
    }

    @Override
    public boolean isReadable(long numBytes) {
      return false;
    }

    @Override
    public boolean isWritable() {
      return false;
    }

    @Override
    public boolean isWritable(long numBytes) {
      return false;
    }

    @Override
    public PacketBuffer clear() {
      return null;
    }

    @Override
    public PacketBuffer markReaderIndex() {
      return null;
    }

    @Override
    public PacketBuffer resetReaderIndex() {
      return null;
    }

    @Override
    public PacketBuffer markWriterIndex() {
      return null;
    }

    @Override
    public PacketBuffer resetWriterIndex() {
      return null;
    }

    @Override
    public PacketBuffer ensureWritable(long minWritableBytes) {
      return null;
    }

    @Override
    public boolean getBoolean(long index) {
      return false;
    }

    @Override
    public byte getByte(long index) {
      return 0;
    }

    @Override
    public short getUnsignedByte(long index) {
      return 0;
    }

    @Override
    public short getShort(long index) {
      return 0;
    }

    @Override
    public short getShortRE(long index) {
      return 0;
    }

    @Override
    public int getUnsignedShort(long index) {
      return 0;
    }

    @Override
    public int getUnsignedShortRE(long index) {
      return 0;
    }

    @Override
    public int getInt(long index) {
      return 0;
    }

    @Override
    public int getIntRE(long index) {
      return 0;
    }

    @Override
    public long getUnsignedInt(long index) {
      return 0;
    }

    @Override
    public long getUnsignedIntRE(long index) {
      return 0;
    }

    @Override
    public long getLong(long index) {
      return 0;
    }

    @Override
    public long getLongRE(long index) {
      return 0;
    }

    @Override
    public float getFloat(long index) {
      return 0;
    }

    @Override
    public float getFloatRE(long index) {
      return 0;
    }

    @Override
    public double getDouble(long index) {
      return 0;
    }

    @Override
    public double getDoubleRE(long index) {
      return 0;
    }

    @Override
    public PacketBuffer getBytes(long index, PacketBuffer dst) {
      return null;
    }

    @Override
    public PacketBuffer getBytes(long index, PacketBuffer dst, long length) {
      return null;
    }

    @Override
    public PacketBuffer getBytes(long index, PacketBuffer dst, long dstIndex, long length) {
      return null;
    }

    @Override
    public PacketBuffer getBytes(long index, byte[] dst) {
      return null;
    }

    @Override
    public PacketBuffer getBytes(long index, byte[] dst, long dstIndex, long length) {
      return null;
    }

    @Override
    public CharSequence getCharSequence(long index, long length, Charset charset) {
      return null;
    }

    @Override
    public PacketBuffer setBoolean(long index, boolean value) {
      return null;
    }

    @Override
    public PacketBuffer setByte(long index, int value) {
      return null;
    }

    @Override
    public PacketBuffer setShort(long index, int value) {
      return null;
    }

    @Override
    public PacketBuffer setShortRE(long index, int value) {
      return null;
    }

    @Override
    public PacketBuffer setInt(long index, int value) {
      return null;
    }

    @Override
    public PacketBuffer setIntRE(long index, int value) {
      return null;
    }

    @Override
    public PacketBuffer setLong(long index, long value) {
      return null;
    }

    @Override
    public PacketBuffer setLongRE(long index, long value) {
      return null;
    }

    @Override
    public PacketBuffer setFloat(long index, float value) {
      return null;
    }

    @Override
    public PacketBuffer setFloatRE(long index, float value) {
      return null;
    }

    @Override
    public PacketBuffer setDouble(long index, double value) {
      return null;
    }

    @Override
    public PacketBuffer setDoubleRE(long index, double value) {
      return null;
    }

    @Override
    public PacketBuffer setBytes(long index, PacketBuffer src) {
      return null;
    }

    @Override
    public PacketBuffer setBytes(long index, PacketBuffer src, long length) {
      return null;
    }

    @Override
    public PacketBuffer setBytes(long index, PacketBuffer src, long srcIndex, long length) {
      return null;
    }

    @Override
    public PacketBuffer setBytes(long index, byte[] src) {
      return null;
    }

    @Override
    public PacketBuffer setBytes(long index, byte[] src, long srcIndex, long length) {
      return null;
    }

    @Override
    public PacketBuffer setCharSequence(long index, CharSequence sequence, Charset charset) {
      return null;
    }

    @Override
    public boolean readBoolean() {
      return false;
    }

    @Override
    public byte readByte() {
      return 0;
    }

    @Override
    public short readUnsignedByte() {
      return 0;
    }

    @Override
    public short readShort() {
      return 0;
    }

    @Override
    public short readShortRE() {
      return 0;
    }

    @Override
    public int readUnsignedShort() {
      return 0;
    }

    @Override
    public int readUnsignedShortRE() {
      return 0;
    }

    @Override
    public int readInt() {
      return 0;
    }

    @Override
    public int readIntRE() {
      return 0;
    }

    @Override
    public long readUnsignedInt() {
      return 0;
    }

    @Override
    public long readUnsignedIntRE() {
      return 0;
    }

    @Override
    public long readLong() {
      return 0;
    }

    @Override
    public long readLongRE() {
      return 0;
    }

    @Override
    public float readFloat() {
      return 0;
    }

    @Override
    public float readFloatRE() {
      return 0;
    }

    @Override
    public double readDouble() {
      return 0;
    }

    @Override
    public double readDoubleRE() {
      return 0;
    }

    @Override
    public PacketBuffer readBytes(PacketBuffer dst) {
      return null;
    }

    @Override
    public PacketBuffer readBytes(PacketBuffer dst, long length) {
      return null;
    }

    @Override
    public PacketBuffer readBytes(PacketBuffer dst, long dstIndex, long length) {
      return null;
    }

    @Override
    public PacketBuffer readBytes(byte[] dst) {
      return null;
    }

    @Override
    public PacketBuffer readBytes(byte[] dst, long dstIndex, long length) {
      return null;
    }

    @Override
    public PacketBuffer skipBytes(long length) {
      return null;
    }

    @Override
    public CharSequence readCharSequence(long length, Charset charset) {
      return null;
    }

    @Override
    public PacketBuffer writeBoolean(boolean value) {
      return null;
    }

    @Override
    public PacketBuffer writeByte(int value) {
      return null;
    }

    @Override
    public PacketBuffer writeShort(int value) {
      return null;
    }

    @Override
    public PacketBuffer writeShortRE(int value) {
      return null;
    }

    @Override
    public PacketBuffer writeInt(int value) {
      return null;
    }

    @Override
    public PacketBuffer writeIntRE(int value) {
      return null;
    }

    @Override
    public PacketBuffer writeLong(long value) {
      return null;
    }

    @Override
    public PacketBuffer writeLongRE(long value) {
      return null;
    }

    @Override
    public PacketBuffer writeFloat(float value) {
      return null;
    }

    @Override
    public PacketBuffer writeFloatRE(float value) {
      return null;
    }

    @Override
    public PacketBuffer writeDouble(double value) {
      return null;
    }

    @Override
    public PacketBuffer writeDoubleRE(double value) {
      return null;
    }

    @Override
    public PacketBuffer writeBytes(PacketBuffer src) {
      return null;
    }

    @Override
    public PacketBuffer writeBytes(PacketBuffer src, long length) {
      return null;
    }

    @Override
    public PacketBuffer writeBytes(PacketBuffer src, long srcIndex, long length) {
      return null;
    }

    @Override
    public PacketBuffer writeBytes(byte[] src) {
      return null;
    }

    @Override
    public PacketBuffer writeBytes(byte[] src, long srcIndex, long length) {
      return null;
    }

    @Override
    public PacketBuffer writeCharSequence(CharSequence sequence, Charset charset) {
      return null;
    }

    @Override
    public PacketBuffer copy() {
      return null;
    }

    @Override
    public PacketBuffer copy(long index, long length) {
      return null;
    }

    @Override
    public PacketBuffer slice() {
      return null;
    }

    @Override
    public PacketBuffer slice(long index, long length) {
      return null;
    }

    @Override
    public PacketBuffer duplicate() {
      return null;
    }

    @Override
    public ByteOrder byteOrder() {
      return null;
    }

    @Override
    public PacketBuffer byteOrder(ByteOrder byteOrder) {
      return null;
    }

    @Override
    public long memoryAddress() throws IllegalAccessException {
      return 0;
    }

    @Override
    public boolean release() {
      return false;
    }

    @Override
    public <T extends Packet.Abstract> T cast(Class<T> t) {
      return null;
    }

    @Override
    public void close() {}
  }
}

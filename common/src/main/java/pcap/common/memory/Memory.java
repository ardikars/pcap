/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import pcap.common.annotation.Inclubating;

/**
 * Used to wrap low-level memory address.
 *
 * <p>Creation of a buffer
 *
 * <p>It is recommended to create a new buffer using the helper methods in {@link MemoryAllocator}
 * rather than calling an individual implementation's constructor.
 *
 * <p>
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public interface Memory {

  /** @return returns the number of bytes (octets) this buffer can contain. */
  long capacity();

  /**
   * Adjusts the capacity of this buffer. If the {@code newCapacity} is less than the current
   * capacity, the content of this buffer is truncated. If the {@code newCapacity} is greater than
   * the current capacity, the buffer is appended with unspecified data whose length is {@code
   * (newCapacity - currentCapacity)}.
   *
   * @param newCapacity new capacity.
   * @return returns this {@link Memory}.
   */
  Memory capacity(long newCapacity);

  /**
   * If a user attempts to increase the capacity of this buffer beyond the maximum capacity using
   * {@link #capacity(long)} or {@link #ensureWritable(long)}, those methods will raise an {@link
   * IllegalArgumentException}.
   *
   * @return returns the maximum allowed capacity of this buffer.
   */
  long maxCapacity();

  /** @return returns the {@code readerIndex} of this buffer. */
  long readerIndex();

  /**
   * Sets the {@code readerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code readerIndex} is less than {@code 0}
   *     or greater than {@code this.writerIndex}
   * @param readerIndex reader index.
   * @return returns this {@link Memory}.
   */
  Memory readerIndex(long readerIndex);

  /** @return returns the {@code writerIndex} of this buffer. */
  long writerIndex();

  /**
   * Sets the {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code writerIndex} is less than {@code
   *     this.readerIndex} or greater than {@code this.capacity}
   * @param writerIndex writer index.
   * @return returns this {@link Memory}.
   */
  Memory writerIndex(long writerIndex);

  /**
   * Combination of {@code writerIndex(...)} and {@code readerIndex(...)}.
   *
   * @param readerIndex reader index.
   * @param writerIndex writer index.
   * @return returns this {@link Memory}.
   */
  Memory setIndex(long readerIndex, long writerIndex);

  /**
   * @return returns the number of readable bytes which is equal to {@code (this.writerIndex -
   *     this.readerIndex)}.
   */
  long readableBytes();

  /**
   * @return returns the number of writable bytes which is equal to {@code (this.capacity -
   *     this.writerIndex)}.
   */
  long writableBytes();

  /**
   * @return returns the maximum possible number of writable bytes, which is equal to {@code
   *     (this.maxCapacity - this.writerIndex)}.
   */
  long maxWritableBytes();

  /**
   * @return returns {@code true} if and only if {@code (this.writerIndex - this.readerIndex)} is
   *     greater than {@code 0}.
   */
  boolean isReadable();

  /**
   * @return returns {@code true} if and only if this buffer contains equal to or more than the
   *     specified number of elements.
   */
  boolean isReadable(long numBytes);

  /**
   * @return returns {@code true} if and only if {@code (this.capacity - this.writerIndex)} is
   *     greater than {@code 0}.
   */
  boolean isWritable();

  /**
   * @return returns {@code true} if and only if this buffer has enough room to allow writing the
   *     specified number of elements.
   */
  boolean isWritable(long numBytes);

  /**
   * Sets the {@code readerIndex} and {@code writerIndex} of this buffer to {@code 0}. This method
   * is identical to {@link #setIndex(long, long) setIndex(0, 0)}.
   *
   * @return this {@link Memory}.
   */
  Memory clear();

  /**
   * Marks the current {@code readerIndex} in this buffer. You can reposition the current {@code
   * readerIndex} to the marked {@code readerIndex} by calling {@link #resetReaderIndex()}. The
   * initial value of the marked {@code readerIndex} is {@code 0}.
   *
   * @return this {@link Memory}.
   */
  Memory markReaderIndex();

  /**
   * Repositions the current {@code readerIndex} to the marked {@code readerIndex} in this buffer.
   *
   * @throws IndexOutOfBoundsException if the current {@code writerIndex} is less than the marked
   *     {@code readerIndex}
   * @return this {@link Memory}.
   */
  Memory resetReaderIndex();

  /**
   * Marks the current {@code writerIndex} in this buffer. You can reposition the current {@code
   * writerIndex} to the marked {@code writerIndex} by calling {@link #resetWriterIndex()}. The
   * initial value of the marked {@code writerIndex} is {@code 0}.
   *
   * @return this {@link Memory}.
   */
  Memory markWriterIndex();

  /**
   * Repositions the current {@code writerIndex} to the marked {@code writerIndex} in this buffer.
   *
   * @throws IndexOutOfBoundsException if the current {@code readerIndex} is greater than the marked
   *     {@code writerIndex}
   * @return this {@link Memory}.
   */
  Memory resetWriterIndex();

  /**
   * Makes sure the number of {@linkplain #writableBytes() the writable bytes} is equal to or
   * greater than the specified value. If there is enough writable bytes in this buffer, this method
   * returns with no side effect. Otherwise, it raises an {@link IllegalArgumentException}.
   *
   * @param minWritableBytes the expected minimum number of writable bytes
   * @throws IndexOutOfBoundsException if {@link #writerIndex()} + {@code minWritableBytes} &gt;
   *     {@link #maxCapacity()}
   * @return this {@link Memory}.
   */
  Memory ensureWritable(long minWritableBytes);

  /**
   * Gets a boolean at the specified absolute (@code index) in this buffer. This method does not
   * modify the {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 1} is greater than {@code this.capacity}
   * @return boolean value.
   */
  boolean getBoolean(long index);

  /**
   * Gets a byte at the specified absolute {@code index} in this buffer. This method does not modify
   * {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 1} is greater than {@code this.capacity}
   * @return byte value.
   */
  byte getByte(long index);

  /**
   * Gets an unsigned byte at the specified absolute {@code index} in this buffer. This method does
   * not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 1} is greater than {@code this.capacity}
   * @return unsigned byte value stored in {@code short}.
   */
  short getUnsignedByte(long index);

  /**
   * Gets a 16-bit short integer at the specified absolute {@code index} in this buffer. This method
   * does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 2} is greater than {@code this.capacity}
   * @return short value.
   */
  short getShort(long index);

  /**
   * Gets a 16-bit short integer at the specified absolute {@code index} in this buffer in Little
   * Endian Byte Order. This method does not modify {@code readerIndex} or {@code writerIndex} of
   * this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 2} is greater than {@code this.capacity}
   * @return little endian short value.
   */
  short getShortLE(long index);

  /**
   * Gets an unsigned 16-bit short integer at the specified absolute {@code index} in this buffer.
   * This method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 2} is greater than {@code this.capacity}
   * @return unsigned short value stored in {@code integer}.
   */
  int getUnsignedShort(long index);

  /**
   * Gets an unsigned 16-bit short integer at the specified absolute {@code index} in this buffer in
   * Little Endian Byte Order. This method does not modify {@code readerIndex} or {@code
   * writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 2} is greater than {@code this.capacity}
   * @return unsigned little endian short value stored in {@code integer}.
   */
  int getUnsignedShortLE(long index);

  /**
   * Gets a 32-bit integer at the specified absolute {@code index} in this buffer. This method does
   * not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @return integer value.
   */
  int getInt(long index);

  /**
   * Gets a 32-bit integer at the specified absolute {@code index} in this buffer with Little Endian
   * Byte Order. This method does not modify {@code readerIndex} or {@code writerIndex} of this
   * buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @return little endian integer value.
   */
  int getIntLE(long index);

  /**
   * Gets an unsigned 32-bit integer at the specified absolute {@code index} in this buffer. This
   * method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @return unsigned integer value stored in {@code long}.
   */
  long getUnsignedInt(long index);

  /**
   * Gets an unsigned 32-bit integer at the specified absolute {@code index} in this buffer in
   * Little Endian Byte Order. This method does not modify {@code readerIndex} or {@code
   * writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @return unsigned little endian integer value stored in {@code long}.
   */
  long getUnsignedIntLE(long index);

  /**
   * Gets a 64-bit long integer at the specified absolute {@code index} in this buffer. This method
   * does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 8} is greater than {@code this.capacity}
   * @return long value.
   */
  long getLong(long index);

  /**
   * Gets a 64-bit long integer at the specified absolute {@code index} in this buffer in Little
   * Endian Byte Order. This method does not modify {@code readerIndex} or {@code writerIndex} of
   * this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 8} is greater than {@code this.capacity}
   * @return little endian long value.
   */
  long getLongLE(long index);

  /**
   * Gets a 32-bit floating point number at the specified absolute {@code index} in this buffer.
   * This method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @return float value.
   */
  float getFloat(long index);

  /**
   * Gets a 32-bit floating point number at the specified absolute {@code index} in this buffer in
   * Little Endian Byte Order. This method does not modify {@code readerIndex} or {@code
   * writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @return little endian float value.
   */
  float getFloatLE(long index);

  /**
   * Gets a 64-bit floating point number at the specified absolute {@code index} in this buffer.
   * This method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 8} is greater than {@code this.capacity}
   * @return double value.
   */
  double getDouble(long index);

  /**
   * Gets a 64-bit floating point number at the specified absolute {@code index} in this buffer in
   * Little Endian Byte Order. This method does not modify {@code readerIndex} or {@code
   * writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 8} is greater than {@code this.capacity}
   * @return little endian double value.
   */
  double getDoubleLE(long index);

  /**
   * Transfers this buffer's data to the specified destination starting at the specified absolute
   * {@code index} until the destination becomes non-writable. This method is basically same with
   * {@link #getBytes(long, Memory, long, long)}, except that this method increases the {@code
   * writerIndex} of the destination by the number of the transferred bytes while {@link
   * #getBytes(long, Memory, long, long)} does not. This method does not modify {@code readerIndex}
   * or {@code writerIndex} of the source buffer (i.e. {@code this}).
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or if
   *     {@code index + dst.writableBytes} is greater than {@code this.capacity}
   * @param index index.
   * @param dst destination.
   * @return this {@link Memory}.
   */
  Memory getBytes(long index, Memory dst);

  /**
   * Transfers this buffer's data to the specified destination starting at the specified absolute
   * {@code index}. This method is basically same with {@link #getBytes(long, Memory, long, long)},
   * except that this method increases the {@code writerIndex} of the destination by the number of
   * the transferred bytes while {@link #getBytes(long, Memory, long, long)} does not. This method
   * does not modify {@code readerIndex} or {@code writerIndex} of the source buffer (i.e. {@code
   * this}).
   *
   * @param length the number of bytes to transfer
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0}, if
   *     {@code index + length} is greater than {@code this.capacity}, or if {@code length} is
   *     greater than {@code dst.writableBytes}
   * @param index index.
   * @param dst destination.
   * @param length length.
   * @return this {@link Memory}.
   */
  Memory getBytes(long index, Memory dst, long length);

  /**
   * Transfers this buffer's data to the specified destination starting at the specified absolute
   * {@code index}. This method does not modify {@code readerIndex} or {@code writerIndex} of both
   * the source (i.e. {@code this}) and the destination.
   *
   * @param dstIndex the first index of the destination
   * @param length the number of bytes to transfer
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0}, if the
   *     specified {@code dstIndex} is less than {@code 0}, if {@code index + length} is greater
   *     than {@code this.capacity}, or if {@code dstIndex + length} is greater than {@code
   *     dst.capacity}
   * @param index index.
   * @param dst destination.
   * @param dstIndex destination index.
   * @param length length.
   * @return this {@link Memory}.
   */
  Memory getBytes(long index, Memory dst, long dstIndex, long length);

  /**
   * Transfers this buffer's data to the specified destination starting at the specified absolute
   * {@code index}. This method does not modify {@code readerIndex} or {@code writerIndex} of this
   * buffer
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or if
   *     {@code index + dst.length} is greater than {@code this.capacity}
   * @param index index.
   * @param dst destination.
   * @return this {@link Memory}.
   */
  Memory getBytes(long index, byte[] dst);

  /**
   * Transfers this buffer's data to the specified destination starting at the specified absolute
   * {@code index}. This method does not modify {@code readerIndex} or {@code writerIndex} of this
   * buffer.
   *
   * @param dstIndex the first index of the destination
   * @param length the number of bytes to transfer
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0}, if the
   *     specified {@code dstIndex} is less than {@code 0}, if {@code index + length} is greater
   *     than {@code this.capacity}, or if {@code dstIndex + length} is greater than {@code
   *     dst.length}
   * @param index index.
   * @param dst destination.
   * @param dstIndex destinationIndex.
   * @param length length.
   * @return this {@link Memory}.
   */
  Memory getBytes(long index, byte[] dst, long dstIndex, long length);

  /**
   * Gets a {@link CharSequence} with the given length at the given index.
   *
   * @throws IndexOutOfBoundsException if {@code length} is greater than {@code this.readableBytes}
   * @param length the length to read
   * @param charset that should be used
   * @return the sequence
   * @return a string from buffer.
   */
  CharSequence getCharSequence(long index, long length, Charset charset);

  /**
   * Sets the specified boolean at the specified absolute {@code index} in this buffer. This method
   * does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 1} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setBoolean(long index, boolean value);

  /**
   * Sets the specified byte at the specified absolute {@code index} in this buffer. The 24
   * high-order bits of the specified value are ignored. This method does not modify {@code
   * readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 1} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setByte(long index, int value);

  /**
   * Sets the specified 16-bit short integer at the specified absolute {@code index} in this buffer.
   * The 16 high-order bits of the specified value are ignored. This method does not modify {@code
   * readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 2} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setShort(long index, int value);

  /**
   * Sets the specified 16-bit short integer at the specified absolute {@code index} in this buffer
   * with the Little Endian Byte Order. The 16 high-order bits of the specified value are ignored.
   * This method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 2} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setShortLE(long index, int value);

  /**
   * Sets the specified 32-bit integer at the specified absolute {@code index} in this buffer. This
   * method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setInt(long index, int value);

  /**
   * Sets the specified 32-bit integer at the specified absolute {@code index} in this buffer with
   * Little Endian byte order . This method does not modify {@code readerIndex} or {@code
   * writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setIntLE(long index, int value);

  /**
   * Sets the specified 64-bit long integer at the specified absolute {@code index} in this buffer.
   * This method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 8} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setLong(long index, long value);

  /**
   * Sets the specified 64-bit long integer at the specified absolute {@code index} in this buffer
   * in Little Endian Byte Order. This method does not modify {@code readerIndex} or {@code
   * writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 8} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setLongLE(long index, long value);

  /**
   * Sets the specified 32-bit floating-point number at the specified absolute {@code index} in this
   * buffer. This method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setFloat(long index, float value);

  /**
   * Sets the specified 32-bit floating-point number at the specified absolute {@code index} in this
   * buffer in Little Endian Byte Order. This method does not modify {@code readerIndex} or {@code
   * writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 4} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setFloatLE(long index, float value);

  /**
   * Sets the specified 64-bit floating-point number at the specified absolute {@code index} in this
   * buffer. This method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 8} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setDouble(long index, double value);

  /**
   * Sets the specified 64-bit floating-point number at the specified absolute {@code index} in this
   * buffer in Little Endian Byte Order. This method does not modify {@code readerIndex} or {@code
   * writerIndex} of this buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or
   *     {@code index + 8} is greater than {@code this.capacity}
   * @param index index.
   * @param value value.
   * @return this {@link Memory}.
   */
  Memory setDoubleLE(long index, double value);

  /**
   * Transfers the specified source buffer's data to this buffer starting at the specified absolute
   * {@code index} until the source buffer becomes unreadable. This method is basically same with
   * {@link #setBytes(long, Memory, long, long)}, except that this method increases the {@code
   * readerIndex} of the source buffer by the number of the transferred bytes while {@link
   * #setBytes(long, Memory, long, long)} does not. This method does not modify {@code readerIndex}
   * or {@code writerIndex} of the source buffer (i.e. {@code this}).
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or if
   *     {@code index + src.readableBytes} is greater than {@code this.capacity}
   * @param index index.
   * @param src source.
   * @return this {@link Memory}.
   */
  Memory setBytes(long index, Memory src);

  /**
   * Transfers the specified source buffer's data to this buffer starting at the specified absolute
   * {@code index}. This method is basically same with {@link #setBytes(long, Memory, long, long)},
   * except that this method increases the {@code readerIndex} of the source buffer by the number of
   * the transferred bytes while {@link #setBytes(long, Memory, long, long)} does not. This method
   * does not modify {@code readerIndex} or {@code writerIndex} of the source buffer (i.e. {@code
   * this}).
   *
   * @param length the number of bytes to transfer
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0}, if
   *     {@code index + length} is greater than {@code this.capacity}, or if {@code length} is
   *     greater than {@code src.readableBytes}
   * @param index index.
   * @param src source.
   * @param length length.
   * @return this {@link Memory}.
   */
  Memory setBytes(long index, Memory src, long length);

  /**
   * Transfers the specified source buffer's data to this buffer starting at the specified absolute
   * {@code index}. This method does not modify {@code readerIndex} or {@code writerIndex} of both
   * the source (i.e. {@code this}) and the destination.
   *
   * @param srcIndex the first index of the source
   * @param length the number of bytes to transfer
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0}, if the
   *     specified {@code srcIndex} is less than {@code 0}, if {@code index + length} is greater
   *     than {@code this.capacity}, or if {@code srcIndex + length} is greater than {@code
   *     src.capacity}
   * @param index index.
   * @param src source.
   * @param srcIndex source index.
   * @param length length.
   * @return this {@link Memory}.
   */
  Memory setBytes(long index, Memory src, long srcIndex, long length);

  /**
   * Transfers the specified source array's data to this buffer starting at the specified absolute
   * {@code index}. This method does not modify {@code readerIndex} or {@code writerIndex} of this
   * buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0} or if
   *     {@code index + src.length} is greater than {@code this.capacity}
   * @param index index.
   * @param src source.
   * @return this {@link Memory}.
   */
  Memory setBytes(long index, byte[] src);

  /**
   * Transfers the specified source array's data to this buffer starting at the specified absolute
   * {@code index}. This method does not modify {@code readerIndex} or {@code writerIndex} of this
   * buffer.
   *
   * @throws IndexOutOfBoundsException if the specified {@code index} is less than {@code 0}, if the
   *     specified {@code srcIndex} is less than {@code 0}, if {@code index + length} is greater
   *     than {@code this.capacity}, or if {@code srcIndex + length} is greater than {@code
   *     src.length}
   * @param index index.
   * @param src source.
   * @param srcIndex source index.
   * @param length length.
   * @return this {@link Memory}.
   */
  Memory setBytes(long index, byte[] src, long srcIndex, long length);

  /**
   * Writes the specified {@link CharSequence} at the current {@code writerIndex} and increases the
   * {@code writerIndex} by the written bytes.
   *
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is not large enough to write
   *     the whole sequence
   * @param index on which the sequence should be written.
   * @param sequence to write.
   * @param charset that should be used.
   * @return this {@link Memory}.
   */
  Memory setCharSequence(long index, CharSequence sequence, Charset charset);

  /**
   * Gets a boolean at the current {@code readerIndex} and increases the {@code readerIndex} by
   * {@code 1} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 1}
   * @return boolean value.
   */
  boolean readBoolean();

  /**
   * Gets a byte at the current {@code readerIndex} and increases the {@code readerIndex} by {@code
   * 1} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 1}
   * @return byte value.
   */
  byte readByte();

  /**
   * Gets an unsigned byte at the current {@code readerIndex} and increases the {@code readerIndex}
   * by {@code 1} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 1}
   * @return unsigned byte stored in {@code short}.
   */
  short readUnsignedByte();

  /**
   * Gets a 16-bit short integer at the current {@code readerIndex} and increases the {@code
   * readerIndex} by {@code 2} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 2}
   * @return short value.
   */
  short readShort();

  /**
   * Gets a 16-bit short integer at the current {@code readerIndex} in the Little Endian Byte Order
   * and increases the {@code readerIndex} by {@code 2} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 2}
   * @return little endian short value.
   */
  short readShortLE();

  /**
   * Gets an unsigned 16-bit short integer at the current {@code readerIndex} and increases the
   * {@code readerIndex} by {@code 2} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 2}
   * @return unsigned short value stored in {@code integer}.
   */
  int readUnsignedShort();

  /**
   * Gets an unsigned 16-bit short integer at the current {@code readerIndex} in the Little Endian
   * Byte Order and increases the {@code readerIndex} by {@code 2} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 2}
   * @return unsigned little endian short value stored in {@code integer}.
   */
  int readUnsignedShortLE();

  /**
   * Gets a 32-bit integer at the current {@code readerIndex} and increases the {@code readerIndex}
   * by {@code 4} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 4}
   * @return integer value.
   */
  int readInt();

  /**
   * Gets a 32-bit integer at the current {@code readerIndex} in the Little Endian Byte Order and
   * increases the {@code readerIndex} by {@code 4} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 4}
   * @return little endian integer value.
   */
  int readIntLE();

  /**
   * Gets an unsigned 32-bit integer at the current {@code readerIndex} and increases the {@code
   * readerIndex} by {@code 4} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 4}
   * @return unsigned integer value.
   */
  long readUnsignedInt();

  /**
   * Gets an unsigned 32-bit integer at the current {@code readerIndex} in the Little Endian Byte
   * Order and increases the {@code readerIndex} by {@code 4} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 4}
   * @return unsigned little endian integer value.
   */
  long readUnsignedIntLE();

  /**
   * Gets a 64-bit integer at the current {@code readerIndex} and increases the {@code readerIndex}
   * by {@code 8} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 8}
   * @return long value.
   */
  long readLong();

  /**
   * Gets a 64-bit integer at the current {@code readerIndex} in the Little Endian Byte Order and
   * increases the {@code readerIndex} by {@code 8} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 8}
   * @return little endian long value.
   */
  long readLongLE();

  /**
   * Gets a 32-bit floating point number at the current {@code readerIndex} and increases the {@code
   * readerIndex} by {@code 4} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 4}
   * @return float value.
   */
  float readFloat();

  /**
   * Gets a 32-bit floating point number at the current {@code readerIndex} in Little Endian Byte
   * Order and increases the {@code readerIndex} by {@code 4} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 4}
   * @return little endian float value.
   */
  float readFloatLE();

  /**
   * Gets a 64-bit floating point number at the current {@code readerIndex} and increases the {@code
   * readerIndex} by {@code 8} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 8}
   * @return double value.
   */
  double readDouble();

  /**
   * Gets a 64-bit floating point number at the current {@code readerIndex} in Little Endian Byte
   * Order and increases the {@code readerIndex} by {@code 8} in this buffer.
   *
   * @throws IndexOutOfBoundsException if {@code this.readableBytes} is less than {@code 8}
   * @return little endian double value.
   */
  double readDoubleLE();

  /**
   * Transfers this buffer's data to the specified destination starting at the current {@code
   * readerIndex} until the destination becomes non-writable, and increases the {@code readerIndex}
   * by the number of the transferred bytes. This method is basically same with {@link
   * #readBytes(Memory, long, long)}, except that this method increases the {@code writerIndex} of
   * the destination by the number of the transferred bytes while {@link #readBytes(Memory, long,
   * long)} does not.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code dst.writableBytes} is greater than {@code
   *     this.readableBytes}
   */
  Memory readBytes(Memory dst);

  /**
   * Transfers this buffer's data to the specified destination starting at the current {@code
   * readerIndex} and increases the {@code readerIndex} by the number of the transferred bytes (=
   * {@code length}). This method is basically same with {@link #readBytes(Memory, long, long)},
   * except that this method increases the {@code writerIndex} of the destination by the number of
   * the transferred bytes (= {@code length}) while {@link #readBytes(Memory, long, long)} does not.
   *
   * @throws IndexOutOfBoundsException if {@code length} is greater than {@code this.readableBytes}
   *     or if {@code length} is greater than {@code dst.writableBytes}
   */
  Memory readBytes(Memory dst, long length);

  /**
   * Transfers this buffer's data to the specified destination starting at the current {@code
   * readerIndex} and increases the {@code readerIndex} by the number of the transferred bytes (=
   * {@code length}).
   *
   * @param dst destination.
   * @param dstIndex the first index of the destination
   * @param length the number of bytes to transfer
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if the specified {@code dstIndex} is less than {@code 0}, if
   *     {@code length} is greater than {@code this.readableBytes}, or if {@code dstIndex + length}
   *     is greater than {@code dst.capacity}
   */
  Memory readBytes(Memory dst, long dstIndex, long length);

  /**
   * Transfers this buffer's data to the specified destination starting at the current {@code
   * readerIndex} and increases the {@code readerIndex} by the number of the transferred bytes (=
   * {@code dst.length}).
   *
   * @param dst destination.
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code dst.length} is greater than {@code
   *     this.readableBytes}
   */
  Memory readBytes(byte[] dst);

  /**
   * Transfers this buffer's data to the specified destination starting at the current {@code
   * readerIndex} and increases the {@code readerIndex} by the number of the transferred bytes (=
   * {@code length}).
   *
   * @param dst destination.
   * @param dstIndex the first index of the destination
   * @param length the number of bytes to transfer
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if the specified {@code dstIndex} is less than {@code 0}, if
   *     {@code length} is greater than {@code this.readableBytes}, or if {@code dstIndex + length}
   *     is greater than {@code dst.length}
   */
  Memory readBytes(byte[] dst, long dstIndex, long length);

  /**
   * Increases the current {@code readerIndex} by the specified {@code length} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code length} is greater than {@code this.readableBytes}
   */
  Memory skipBytes(long length);

  /**
   * Gets a {@link CharSequence} with the given length at the current {@code readerIndex} and
   * increases the {@code readerIndex} by the given length.
   *
   * @param length the length to read
   * @param charset that should be used
   * @return the char sequence.
   * @throws IndexOutOfBoundsException if {@code length} is greater than {@code this.readableBytes}
   */
  CharSequence readCharSequence(long length, Charset charset);

  /**
   * Sets the specified boolean at the current {@code writerIndex} and increases the {@code
   * writerIndex} by {@code 1} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 1}
   */
  Memory writeBoolean(boolean value);

  /**
   * Sets the specified byte at the current {@code writerIndex} and increases the {@code
   * writerIndex} by {@code 1} in this buffer. The 24 high-order bits of the specified value are
   * ignored.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 1}
   */
  Memory writeByte(int value);

  /**
   * Sets the specified 16-bit short integer at the current {@code writerIndex} and increases the
   * {@code writerIndex} by {@code 2} in this buffer. The 16 high-order bits of the specified value
   * are ignored.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 2}
   */
  Memory writeShort(int value);

  /**
   * Sets the specified 16-bit short integer in the Little Endian Byte Order at the current {@code
   * writerIndex} and increases the {@code writerIndex} by {@code 2} in this buffer. The 16
   * high-order bits of the specified value are ignored.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 2}
   */
  Memory writeShortLE(int value);

  /**
   * Sets the specified 32-bit integer at the current {@code writerIndex} and increases the {@code
   * writerIndex} by {@code 4} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 4}
   */
  Memory writeInt(int value);

  /**
   * Sets the specified 32-bit integer at the current {@code writerIndex} in the Little Endian Byte
   * Order and increases the {@code writerIndex} by {@code 4} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 4}
   */
  Memory writeIntLE(int value);

  /**
   * Sets the specified 64-bit long integer at the current {@code writerIndex} and increases the
   * {@code writerIndex} by {@code 8} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 8}
   */
  Memory writeLong(long value);

  /**
   * Sets the specified 64-bit long integer at the current {@code writerIndex} in the Little Endian
   * Byte Order and increases the {@code writerIndex} by {@code 8} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 8}
   */
  Memory writeLongLE(long value);

  /**
   * Sets the specified 32-bit floating point number at the current {@code writerIndex} and
   * increases the {@code writerIndex} by {@code 4} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 4}
   */
  Memory writeFloat(float value);

  /**
   * Sets the specified 32-bit floating point number at the current {@code writerIndex} in Little
   * Endian Byte Order and increases the {@code writerIndex} by {@code 4} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 4}
   */
  Memory writeFloatLE(float value);

  /**
   * Sets the specified 64-bit floating point number at the current {@code writerIndex} and
   * increases the {@code writerIndex} by {@code 8} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 8}
   */
  Memory writeDouble(double value);

  /**
   * Sets the specified 64-bit floating point number at the current {@code writerIndex} in Little
   * Endian Byte Order and increases the {@code writerIndex} by {@code 8} in this buffer.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is less than {@code 8}
   */
  Memory writeDoubleLE(double value);

  /**
   * Transfers the specified source buffer's data to this buffer starting at the current {@code
   * writerIndex} until the source buffer becomes unreadable, and increases the {@code writerIndex}
   * by the number of the transferred bytes. This method is basically same with {@link
   * #writeBytes(Memory, long, long)}, except that this method increases the {@code readerIndex} of
   * the source buffer by the number of the transferred bytes while {@link #writeBytes(Memory, long,
   * long)} does not.
   *
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code src.readableBytes} is greater than {@code
   *     this.writableBytes}
   */
  Memory writeBytes(Memory src);

  /**
   * Transfers the specified source buffer's data to this buffer starting at the current {@code
   * writerIndex} and increases the {@code writerIndex} by the number of the transferred bytes (=
   * {@code length}). This method is basically same with {@link #writeBytes(Memory, long, long)},
   * except that this method increases the {@code readerIndex} of the source buffer by the number of
   * the transferred bytes (= {@code length}) while {@link #writeBytes(Memory, long, long)} does
   * not.
   *
   * @param src source.
   * @param length the number of bytes to transfer.
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code length} is greater than {@code this.writableBytes}
   *     or if {@code length} is greater then {@code src.readableBytes}
   */
  Memory writeBytes(Memory src, long length);

  /**
   * Transfers the specified source buffer's data to this buffer starting at the current {@code
   * writerIndex} and increases the {@code writerIndex} by the number of the transferred bytes (=
   * {@code length}).
   *
   * @param src source.
   * @param srcIndex the first index of the source
   * @param length the number of bytes to transfer
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if the specified {@code srcIndex} is less than {@code 0}, if
   *     {@code srcIndex + length} is greater than {@code src.capacity}, or if {@code length} is
   *     greater than {@code this.writableBytes}
   */
  Memory writeBytes(Memory src, long srcIndex, long length);

  /**
   * Transfers the specified source array's data to this buffer starting at the current {@code
   * writerIndex} and increases the {@code writerIndex} by the number of the transferred bytes (=
   * {@code src.length}).
   *
   * @param src source.
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if {@code src.length} is greater than {@code
   *     this.writableBytes}
   */
  Memory writeBytes(byte[] src);

  /**
   * Transfers the specified source array's data to this buffer starting at the current {@code
   * writerIndex} and increases the {@code writerIndex} by the number of the transferred bytes (=
   * {@code length}).
   *
   * @param src source.
   * @param srcIndex the first index of the source
   * @param length the number of bytes to transfer
   * @return this {@link Memory}.
   * @throws IndexOutOfBoundsException if the specified {@code srcIndex} is less than {@code 0}, if
   *     {@code srcIndex + length} is greater than {@code src.length}, or if {@code length} is
   *     greater than {@code this.writableBytes}
   */
  Memory writeBytes(byte[] src, long srcIndex, long length);

  /**
   * Writes the specified {@link CharSequence} at the current {@code writerIndex} and increases the
   * {@code writerIndex} by the written bytes. in this buffer.
   *
   * @param sequence to write.
   * @param charset that should be used.
   * @return the written number of bytes.
   * @throws IndexOutOfBoundsException if {@code this.writableBytes} is not large enough to write
   *     the whole sequence
   */
  Memory writeCharSequence(CharSequence sequence, Charset charset);

  /**
   * Returns a copy of this buffer's readable bytes. Modifying the content of the returned buffer or
   * this buffer does not affect each other at all. This method is identical to {@code
   * copy(readerIndex(), readableBytes())}. This method does not modify {@code readerIndex} or
   * {@code writerIndex} of this buffer.
   *
   * @return copied {@link Memory} buffer's.
   */
  Memory copy();

  /**
   * Returns a copy of this buffer's sub-region. Modifying the content of the returned buffer or
   * this buffer does not affect each other at all. This method does not modify {@code readerIndex}
   * or {@code writerIndex} of this buffer.
   *
   * @param index index.
   * @param length length.
   * @return copied {@link Memory} buffer's.
   */
  Memory copy(long index, long length);

  /**
   * Returns a slice of this buffer's readable bytes. Modifying the content of the returned buffer
   * or this buffer affects each other's content while they maintain separate indexes and marks.
   * This method is identical to {@code slice(readerIndex(), readableBytes())}. This method does not
   * modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @return returns sliced {@link Memory} buffer's.
   */
  Memory slice();

  /**
   * Returns a slice of this buffer's sub-region. Modifying the content of the returned buffer or
   * this buffer affects each other's content while they maintain separate indexes and marks. This
   * method does not modify {@code readerIndex} or {@code writerIndex} of this buffer.
   *
   * @param index index.
   * @param length length.
   * @return returns sliced {@link Memory} buffer's.
   */
  Memory slice(long index, long length);

  /**
   * Duplicate the this {@link Memory} buffer. Modifying the content of the returned buffer or this
   * buffer affects each other's content while they maintain separate indexes and marks
   *
   * @return returns duplicated {@link Memory}.
   */
  Memory duplicate();

  /**
   * Retrieves this buffer's byte order.
   *
   * @return returns {@link ByteOrder#BIG_ENDIAN} or {@link ByteOrder#LITTLE_ENDIAN}.
   */
  ByteOrder byteOrder();

  /**
   * Change this buffer's byte order.
   *
   * @param byteOrder byte order.
   * @return returns this buffer's with new byte order.
   */
  Memory byteOrder(ByteOrder byteOrder);

  /** Release this {@link Memory} buffer */
  @Inclubating
  boolean release();

  /**
   * Exposes this {@link Memory} buffer's as an NIO {@link ByteBuffer}'s. The returned buffer either
   * share or contains the copied content of this buffer, while changing the position and limit of
   * the returned NIO buffer does not affect the indexes and marks of this buffer. This method does
   * not modify {@code readerIndex} or {@code writerIndex} of this buffer. Please note that the
   * returned NIO buffer will not see the changes of this buffer if this buffer is a dynamic buffer
   * and it adjusted its capacity and returned NIO buffer has no cleaner.
   *
   * @return returns direct {@link ByteBuffer} with no cleaner.
   */
  @Inclubating
  ByteBuffer nioBuffer();

  <T> T buffer(Class<T> clazz);

  /** Byte order. */
  enum ByteOrder {
    BIG_ENDIAN,
    LITTLE_ENDIAN;
    public static ByteOrder NATIVE =
        java.nio.ByteOrder.nativeOrder() == java.nio.ByteOrder.BIG_ENDIAN
            ? ByteOrder.BIG_ENDIAN
            : ByteOrder.LITTLE_ENDIAN;
  }

  /** Indicate the buffer is sliced. */
  @Inclubating
  interface Sliced {

    /**
     * Unslice buffer.
     *
     * @return returns unsliced {@link Memory} buffer.
     */
    Memory unSlice();
  }

  /** Indicate the buffer is direct buffer (off-heap buffer). */
  @Inclubating
  interface Direct<A> {

    /**
     * @return returns the low-level memory address that point to the first byte of ths backing
     *     data.
     */
    @Inclubating
    A memoryAddress();
  }

  /** Indicate the buffer is heap buffer. */
  @Inclubating
  interface Heap {}

  /** Indicate the buffer is pooled buffer. */
  @Inclubating
  interface Pooled {

    /** Memory id. */
    @Inclubating
    int id();

    /** Reference counter. */
    @Inclubating
    int refCnt();

    /** Decrement reference counter by spesific delta. */
    @Inclubating
    int refCnt(int cnt);

    /** Increment reference counter. */
    @Inclubating
    int retain();

    /** Increment reference counter by spesific delte. */
    @Inclubating
    int retain(int retain);
  }
}

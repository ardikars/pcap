/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.memory.accessor;

import java.nio.ByteBuffer;

/**
 * Abstraction over an address space of readable and writable bytes,
 * also can used to allocate/reallocate/deallocate buffer's.
 * <p>
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface MemoryAccessor {

    /**
     * Allocate memory buffer's with given size.
     * @param size size of buffer (in bytes).
     * @return returns memory address of begining bytes.
     */
    long allocate(int size);

    /**
     * If the dynamically allocated memory is insufficient or more than required,
     * you can change the size of previously allocated memory using this funtions.
     * @param addr memory address.
     * @param size new size of buffer (in bytes).
     * @return returns memory current address.
     */
    long reallocate(long addr, int size);

    /**
     * Release/freeing block of memory.
     * @param addr memory address.
     */
    void deallocate(long addr);

    /**
     * Wrap low-lavel memory into direct {@link ByteBuffer} with no cleaner.
     * @param addr memory address.
     * @param size size of memory block.
     * @return returns direct {@link ByteBuffer} with no cleaner.
     */
    ByteBuffer nioBuffer(long addr, int size);

    /**
     * Reads the byte value from given address.
     *
     * @param addr the address where the byte value will be read from.
     * @return the byte value that was read.
     */
    byte getByte(long addr);

    /**
     * Reads the short value from given address.
     *
     * @param addr the address where the short value will be read from.
     * @return the short value that was read.
     */
    short getShort(long addr);

    /**
     * Reads the little endian short value from given address.
     *
     * @param addr the address where the short value will be read from.
     * @return the little endian short value that was read.
     */
    short getShortLE(long addr);

    /**
     * Reads the int value from given address.
     *
     * @param addr the address where the int value will be read from.
     * @return the int value that was read.
     */
    int getInt(long addr);

    /**
     * Reads the little endian int value from given address.
     *
     * @param addr the address where the int value will be read from.
     * @return the little indian int value that was read.
     */
    int getIntLE(long addr);

    /**
     * Reads the long value from given address.
     *
     * @param addr the address where the long value will be read from.
     * @return the long value that was read.
     */
    long getLong(long addr);

    /**
     * Reads the little endian long value from given address.
     *
     * @param addr the address where the long value will be read from.
     * @return the little endian long value that was read.
     */
    long getLongLE(long addr);

    /**
     * Copies memory from given source address and source index to given destination address
     * as given destination index and size.
     *
     * @param srcAddr the source address to be copied from.
     * @param index the source address (specified offset).
     * @param dstAddr the destination address to be copied to.
     * @param dstIndex the destination address (specified offset) to be copied to.
     * @param size the number of bytes to be copied.
     */
    void getBytes(long srcAddr, int index, long dstAddr, int dstIndex, int size);

    /**
     * Copies memory from given source address and source index to a Java byte array.
     *
     * @param srcAddr the source address to be copied from.
     * @param index the source address (specified offset).
     * @param dst the destination byte array.
     * @param dstIndex the destination byte array offset to be copied.
     * @param size number of bytes to copy.
     */
    void getBytes(long srcAddr, int index, byte[] dst, int dstIndex, int size);

    /**
     * Writes the given byte value to given address.
     *
     * @param addr the address where the byte value will be written to.
     * @param val the byte value to be written.
     */
    void setByte(long addr, int val);

    /**
     * Writes the given short value to given address.
     *
     * @param addr the address where the short value will be written to.
     * @param val the short value to be written.
     */
    void setShort(long addr, int val);

    /**
     * Writes the given little endian short value to given address.
     *
     * @param addr the address where the little endian short value will be written to.
     * @param val the little endian short value to be written.
     */
    void setShortLE(long addr, int val);

    /**
     * Writes the given int value to given address.
     *
     * @param addr the address where the int value will be written to.
     * @param val the int value to be written.
     */
    void setInt(long addr, int val);

    /**
     * Writes the given little endian int value to given address.
     *
     * @param addr the address where the little endian int value will be written to.
     * @param val the little endian int value to be written.
     */
    void setIntLE(long addr, int val);

    /**
     * Writes the given long value to given address.
     *
     * @param addr the address where the long value will be written to.
     * @param val the long value to be written.
     */
    void setLong(long addr, long val);

    /**
     * Writes the given little endian long value to given address.
     *
     * @param addr the address where the little endian long value will be written to.
     * @param val the little endian long value to be written.
     */
    void setLongLE(long addr, long val);

    /**
     * Copies memory from given source address and source index to given destination address
     * as given destination index and size.
     *
     * @param dstAddr the destination address to be copied to.
     * @param index the destination address (specified offset) to be copied to.
     * @param srcAddr the source address to be copied from.
     * @param srcIndex the source address (specified offset).
     * @param size the number of bytes to be copied.
     */
    void setBytes(long dstAddr, int index, long srcAddr, int srcIndex, int size);

    /**
     * Copies bytes from a Java byte array into this accessor's address space.
     * @param dstAddr address where the first byte will be written.
     * @param index the destination address (specified offset) to be copied to.
     * @param src source byte array.
     * @param srcIndex the offset of source byte array.
     * @param size the number of bytes to be copied.
     */
    void setBytes(long dstAddr, int index, byte[] src, int srcIndex, int size);

}

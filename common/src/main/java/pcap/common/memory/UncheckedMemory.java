package pcap.common.memory;

import pcap.common.internal.UnsafeHelper;

import java.nio.ByteBuffer;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
class UncheckedMemory extends AbstractMemory {

    long address;

    UncheckedMemory(long address, int capacity, int maxCapacity) {
        super(capacity, maxCapacity);
        this.address = address;
    }

    UncheckedMemory(long address, int capacity, int maxCapacity, int readerIndex, int writerIndex) {
        super(capacity, maxCapacity, readerIndex, writerIndex);
        this.address = address;
    }

    @Override
    public UncheckedMemory capacity(int newCapacity) {
        checkNewCapacity(newCapacity);
        this.address = ACCESSOR.reallocate(address, newCapacity);
        this.capacity = newCapacity;
        this.maxCapacity = maxCapacity > newCapacity ? maxCapacity : newCapacity;
        return this;
    }

    @Override
    public byte getByte(int index) {
        return ACCESSOR.getByte(addr(index));
    }

    @Override
    public short getShort(int index) {
        return ACCESSOR.getShort(addr(index));
    }

    @Override
    public short getShortLE(int index) {
        return ACCESSOR.getShortLE(addr(index));
    }

    @Override
    public int getInt(int index) {
        return ACCESSOR.getInt(addr(index));
    }

    @Override
    public int getIntLE(int index) {
        return ACCESSOR.getIntLE(addr(index));
    }

    @Override
    public long getLong(int index) {
        return ACCESSOR.getLong(addr(index));
    }

    @Override
    public long getLongLE(int index) {
        return ACCESSOR.getLongLE(addr(index));
    }

    @Override
    public UncheckedMemory getBytes(int index, Memory dst, int dstIndex, int length) {
        ACCESSOR.getBytes(address, index, dst.memoryAddress(), dstIndex, length);
        return this;
    }

    @Override
    public UncheckedMemory getBytes(int index, byte[] dst, int dstIndex, int length) {
        ACCESSOR.getBytes(address, index, dst, dstIndex, length);
        return this;
    }

    @Override
    public UncheckedMemory readBytes(Memory dst, int length) {
        readBytes(dst, dst.writerIndex(), length);
        dst.writerIndex(dst.writerIndex() + length);
        return this;
    }

    @Override
    public UncheckedMemory setByte(int index, int value) {
        ACCESSOR.setByte(addr(index), value);
        return this;
    }

    @Override
    public UncheckedMemory setShort(int index, int value) {
        ACCESSOR.setShort(addr(index), value);
        return this;
    }

    @Override
    public UncheckedMemory setShortLE(int index, int value) {
        ACCESSOR.setShortLE(addr(index), value);
        return this;
    }

    @Override
    public UncheckedMemory setInt(int index, int value) {
        ACCESSOR.setInt(addr(index), value);
        return this;
    }

    @Override
    public UncheckedMemory setIntLE(int index, int value) {
        ACCESSOR.setIntLE(addr(index), value);
        return this;
    }

    @Override
    public UncheckedMemory setLong(int index, long value) {
        ACCESSOR.setLong(addr(index), value);
        return this;
    }

    @Override
    public UncheckedMemory setLongLE(int index, long value) {
        ACCESSOR.setLongLE(addr(index), value);
        return this;
    }

    @Override
    public UncheckedMemory setBytes(int index, Memory src, int srcIndex, int length) {
        ACCESSOR.setBytes(address, index, src.memoryAddress(), srcIndex, length);
        return this;
    }

    @Override
    public UncheckedMemory setBytes(int index, byte[] src, int srcIndex, int length) {
        ACCESSOR.setBytes(address, index, src, srcIndex, length);
        return this;
    }

    @Override
    public UncheckedMemory writeBytes(Memory src, int length) {
        writeBytes(src, src.readerIndex(), length);
        src.readerIndex(src.readerIndex() + length);
        return this;
    }

    @Override
    public boolean isDirect() {
        return true;
    }

    @Override
    public long memoryAddress() {
        return address;
    }

    @Override
    public UncheckedMemory copy(int index, int length) {
        long newAddress = ACCESSOR.allocate(length);
        UncheckedMemory memory = new UncheckedMemory(newAddress, length, maxCapacity, readerIndex(), writerIndex());
        if (length != 0) {
            memory.setBytes(0, this, index, length);
        }
        return memory;
    }

    @Override
    public UncheckedMemory slice(int index, int length) {
        return new SlicedUncheckedMemory(address, capacity, address + index, length, maxCapacity, readerIndex() - index, writerIndex() - index);
    }

    @Override
    public UncheckedMemory duplicate() {
        UncheckedMemory memory = new UncheckedMemory(address, capacity, maxCapacity, readerIndex(), writerIndex());
        return memory;
    }

    @Override
    public ByteBuffer nioBuffer() {
        return ACCESSOR.nioBuffer(memoryAddress(), capacity);
    }

    @Override
    public void release() {
        if (!freed) {
            UnsafeHelper.getUnsafe().freeMemory(memoryAddress());
            freed = true;
        }
    }

    final long addr(int index) {
        return address + index;
    }

}

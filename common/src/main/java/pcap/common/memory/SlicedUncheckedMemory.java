package pcap.common.memory;

import java.nio.ByteBuffer;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
class SlicedUncheckedMemory extends UncheckedMemory {

    private final long baseAddress;
    private final int baseCapacity;

    public SlicedUncheckedMemory(long baseAddress, int baseCapacity, long address, int capacity, int maxCapacity, int readerIndex, int writerIndex) {
        super(address, capacity, maxCapacity, readerIndex, writerIndex);
        this.baseAddress = baseAddress;
        this.baseCapacity = baseCapacity;
    }

    @Override
    public ByteBuffer nioBuffer() {
        return ACCESSOR.nioBuffer(baseAddress, baseCapacity);
    }

    @Override
    public void release() {
        if (!freed) {
            ACCESSOR.deallocate(baseAddress);
        }
    }

}

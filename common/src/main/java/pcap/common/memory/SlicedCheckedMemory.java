/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.memory;

import java.nio.ByteBuffer;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
class SlicedCheckedMemory extends CheckedMemory {

    private final long baseAddress;
    private final int baseCapacity;

    public SlicedCheckedMemory(long baseAddress, int baseCapacity, long address, int capacity, int maxCapacity, int readerIndex, int writerIndex) {
        super(address, capacity, maxCapacity, readerIndex, writerIndex);
        this.baseAddress = baseAddress;
        this.baseCapacity = baseCapacity;
    }

    @Override
    public ByteBuffer nioBuffer() {
        ensureAccessible(0, baseCapacity);
        return ACCESSOR.nioBuffer(baseAddress, baseCapacity);
    }

    @Override
    public void release() {
        if (!freed) {
            ACCESSOR.deallocate(baseAddress);
        }
    }

}

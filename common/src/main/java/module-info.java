module pcap.common {
  requires org.apache.logging.log4j;
  requires org.slf4j;

  exports pcap.common.annotation;
  exports pcap.common.logging;
  exports pcap.common.memory;
  exports pcap.common.net;
  exports pcap.common.util;
  exports pcap.common.memory.internal.nio to
      pcap.api,
      pcap.codec;

  uses pcap.common.memory.MemoryAllocator;

  provides pcap.common.memory.MemoryAllocator with
      pcap.common.memory.internal.nio.allocator.DirectMemoryAllocator,
      pcap.common.memory.internal.nio.allocator.HeapMemoryAllocator,
      pcap.common.memory.internal.nio.allocator.PooledDirectByteBufferAllocator,
      pcap.common.memory.internal.nio.allocator.PooledHeapByteBufferAllocator;
}

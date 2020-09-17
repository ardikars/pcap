package pcap.api.jdk7;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import java.util.ArrayList;
import java.util.List;
import pcap.spi.PacketBuffer;

public class DefaultPacketBuffer extends StructureReference implements PacketBuffer {

  public Pointer buf;
  private long readerIndex;
  private long writerIndex;

  public DefaultPacketBuffer() {}

  public DefaultPacketBuffer(long size) {
    this(new Memory(size), size);
  }

  public DefaultPacketBuffer(Pointer pointer, long size) {
    super(pointer);
    this.buf = pointer;
    this.readerIndex = 0;
    this.writerIndex = size;
    setBuffer((int) size);
  }

  @Override
  public long readerIndex() {
    return readerIndex;
  }

  @Override
  public DefaultPacketBuffer readerIndex(long readerIndex) {
    this.readerIndex = readerIndex;
    return this;
  }

  @Override
  public long writerIndex() {
    return writerIndex;
  }

  @Override
  public DefaultPacketBuffer writerIndex(long writerIndex) {
    this.writerIndex = writerIndex;
    return this;
  }

  @Override
  public long capacity() {
    return buffer.capacity();
  }

  @Override
  public long address() {
    return 0;
  }

  @Override
  public boolean release() {
    return false;
  }

  @Override
  protected List<String> getFieldOrder() {
    List<String> fieldOrder = new ArrayList<>();
    fieldOrder.add("buf");
    return fieldOrder;
  }
}

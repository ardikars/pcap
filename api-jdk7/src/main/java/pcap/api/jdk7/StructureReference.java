package pcap.api.jdk7;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;
import java.nio.ByteBuffer;

public class StructureReference extends Structure {

  final PointerByReference reference;

  ByteBuffer buffer;

  private boolean bufferRef;
  private boolean fromReference;
  private boolean fromPointerByReference;

  public StructureReference() {
    super();
    this.reference = new PointerByReference();
  }

  public StructureReference(Pointer pointer) {
    super(pointer);
    this.reference = new PointerByReference(pointer);
    read();
  }

  void useMemoryFromReferece() {
    if (!fromReference) {
      if (reference.getValue() != null) {
        super.useMemory(reference.getValue(), 0);
        fromReference = true;
      }
    }
  }

  void useMemoryFromReferece(PointerByReference reference) {
    if (!fromPointerByReference) {
      if (reference.getValue() != null) {
        super.useMemory(reference.getValue(), 0);
        fromPointerByReference = true;
      }
    }
  }

  void setBuffer(int size) {
    if (!bufferRef) {
      if (reference.getValue() != null) {
        buffer = reference.getValue().getByteBuffer(0, size);
      } else {
        buffer = getPointer().getByteBuffer(0, size);
      }
      bufferRef = true;
    }
  }
}

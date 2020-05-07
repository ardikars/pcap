/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@RunWith(JUnitPlatform.class)
public class BytesTest {

  @Test
  public void toByteArray() {
    Assertions.assertEquals(new byte[] {(byte) 253}[0], Bytes.toByteArray((byte) 253)[0]);
  }

  @Test
  public void toByteArrayShortValueBE() {
    int byteSize = 2;

    short value = (short) 65533;
    ByteBuffer byteBuffer = ByteBuffer.allocate(byteSize).order(ByteOrder.BIG_ENDIAN);
    byteBuffer.putShort(value);

    byte[] bytes = Bytes.toByteArray(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    Assertions.assertEquals(value, byteBuffer.getShort());
  }

  @Test
  public void toByteArrayShortValueLE() {
    int byteSize = 2;

    short value = (short) 65533;
    ByteBuffer byteBuffer = ByteBuffer.allocate(byteSize).order(ByteOrder.LITTLE_ENDIAN);
    byteBuffer.putShort(value);

    byte[] bytes = Bytes.toByteArray(value, ByteOrder.LITTLE_ENDIAN);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    Assertions.assertEquals(value, byteBuffer.getShort());
  }

  @Test
  public void toByteArrayShortArrayValueBE() {
    int byteSize = 2;

    short[] value = new short[] {(short) 3, (short) 65533};
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * value.length).order(ByteOrder.BIG_ENDIAN);
    for (int i = 0; i < value.length; i++) {
      byteBuffer.putShort(value[i]);
    }

    byte[] bytes = Bytes.toByteArray(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    for (int i = 0; i < value.length; i++) {
      Assertions.assertEquals(value[i], byteBuffer.getShort());
    }
  }

  @Test
  public void toByteArrayShortArrayValueLE() {
    int byteSize = 2;

    short[] value = new short[] {(short) 3, (short) 65533};
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * value.length).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < value.length; i++) {
      byteBuffer.putShort(value[i]);
    }

    byte[] bytes = Bytes.toByteArray(value, ByteOrder.LITTLE_ENDIAN);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    for (int i = 0; i < value.length; i++) {
      Assertions.assertEquals(value[i], byteBuffer.getShort());
    }
  }

  @Test
  public void toByteArrayIntegerValueBE() {
    int byteSize = 4;

    int value = 2147483643;
    ByteBuffer byteBuffer = ByteBuffer.allocate(byteSize).order(ByteOrder.BIG_ENDIAN);
    byteBuffer.putInt(value);

    byte[] bytes = Bytes.toByteArray(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    Assertions.assertEquals(value, byteBuffer.getInt());
  }

  @Test
  public void toByteArrayIntegerValueLE() {
    int byteSize = 4;

    int value = 2147483643;
    ByteBuffer byteBuffer = ByteBuffer.allocate(byteSize).order(ByteOrder.LITTLE_ENDIAN);
    byteBuffer.putInt(value);

    byte[] bytes = Bytes.toByteArray(value, ByteOrder.LITTLE_ENDIAN);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    Assertions.assertEquals(value, byteBuffer.getInt());
  }

  @Test
  public void toByteArrayIntegerArrayValueBE() {
    int byteSize = 4;

    int[] value = new int[] {3, 2147483643};
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * value.length).order(ByteOrder.BIG_ENDIAN);
    for (int i = 0; i < value.length; i++) {
      byteBuffer.putInt(value[i]);
    }

    byte[] bytes = Bytes.toByteArray(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    for (int i = 0; i < value.length; i++) {
      Assertions.assertEquals(value[i], byteBuffer.getInt());
    }
  }

  @Test
  public void toByteArrayLongValueBE() {
    int byteSize = 8;

    long value = 9223372036854775805L;
    ByteBuffer byteBuffer = ByteBuffer.allocate(byteSize).order(ByteOrder.BIG_ENDIAN);
    byteBuffer.putLong(value);

    byte[] bytes = Bytes.toByteArray(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    Assertions.assertEquals(value, byteBuffer.getLong());
  }

  @Test
  public void toByteArrayLongValueLE() {
    int byteSize = 8;

    long value = 9223372036854775805L;
    ByteBuffer byteBuffer = ByteBuffer.allocate(byteSize).order(ByteOrder.LITTLE_ENDIAN);
    byteBuffer.putLong(value);

    byte[] bytes = Bytes.toByteArray(value, ByteOrder.LITTLE_ENDIAN);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    Assertions.assertEquals(value, byteBuffer.getLong());
  }

  @Test
  public void toByteArrayLongArrayValueBE() {
    int byteSize = 8;

    long[] value = new long[] {3L, 9223372036854775805L};
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * value.length).order(ByteOrder.BIG_ENDIAN);
    for (int i = 0; i < value.length; i++) {
      byteBuffer.putLong(value[i]);
    }

    byte[] bytes = Bytes.toByteArray(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    for (int i = 0; i < value.length; i++) {
      Assertions.assertEquals(value[i], byteBuffer.getLong());
    }
  }

  @Test
  public void toByteArrayLongArrayValueE() {
    int byteSize = 8;

    long[] value = new long[] {3L, 9223372036854775805L};
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * value.length).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < value.length; i++) {
      byteBuffer.putLong(value[i]);
    }

    byte[] bytes = Bytes.toByteArray(value, ByteOrder.LITTLE_ENDIAN);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    for (int i = 0; i < value.length; i++) {
      Assertions.assertEquals(value[i], byteBuffer.getLong());
    }
  }
}

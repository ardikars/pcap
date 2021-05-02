/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.common.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** */
@RunWith(JUnitPlatform.class)
class BytesTest {

  @Test
  void toByteArray() {
    Assertions.assertEquals(new byte[] {(byte) 253}[0], Bytes.toByteArray((byte) 253)[0]);
  }

  @Test
  void toByteArrayShortValueBE() {
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
  void toByteArrayShortValueLE() {
    int byteSize = 2;

    short value = (short) 65533;
    ByteBuffer byteBuffer = ByteBuffer.allocate(byteSize).order(ByteOrder.LITTLE_ENDIAN);
    byteBuffer.putShort(value);

    byte[] bytes = Bytes.toByteArrayLE(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    Assertions.assertEquals(value, byteBuffer.getShort());
  }

  @Test
  void toByteArrayShortArrayValueBE() {
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
  void toByteArrayShortArrayValueBEWithOffsetAndLength() {
    int byteSize = 2;

    short[] values =
        new short[] {
          (short) 0, (short) 1, (short) 2, (short) 3, (short) 4, (short) 5, (short) 6, (short) 7,
          (short) 8, (short) 9
        };
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * values.length).order(ByteOrder.BIG_ENDIAN);
    for (int i = 0; i < values.length; i++) {
      byteBuffer.putShort(values[i]);
    }
    int offset = 5;
    int length = 5;
    byte[] bytes = Bytes.toByteArray(values, offset, length);
    byte[] buffer = byteBuffer.array();
    int index = 0;
    Assertions.assertEquals(bytes.length, length * byteSize);
    for (int i = offset; i < offset + length; i++) {
      Assertions.assertEquals(values[i], Shorts.toShort(bytes, index));
      Assertions.assertEquals(values[i], Shorts.toShort(buffer, (index + offset * byteSize)));
      index += byteSize;
    }
  }

  @Test
  void toByteArrayShortArrayValueLE() {
    int byteSize = 2;

    short[] value = new short[] {(short) 3, (short) 65533};
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * value.length).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < value.length; i++) {
      byteBuffer.putShort(value[i]);
    }

    byte[] bytes = Bytes.toByteArrayLE(value);
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
  void toByteArrayShortArrayValueLEWithOffsetAndLength() {
    int byteSize = 2;

    short[] values =
        new short[] {
          (short) 0, (short) 1, (short) 2, (short) 3, (short) 4, (short) 5, (short) 6, (short) 7,
          (short) 8, (short) 9
        };
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * values.length).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < values.length; i++) {
      byteBuffer.putShort(values[i]);
    }
    int offset = 5;
    int length = 5;
    byte[] bytes = Bytes.toByteArrayLE(values, offset, length);
    byte[] buffer = byteBuffer.array();
    int index = 0;
    Assertions.assertEquals(bytes.length, length * byteSize);
    for (int i = offset; i < offset + length; i++) {
      Assertions.assertEquals(values[i], Shorts.toShortLE(bytes, index));
      Assertions.assertEquals(values[i], Shorts.toShortLE(buffer, (index + offset * byteSize)));
      index += byteSize;
    }
  }

  @Test
  void toByteArrayIntegerValueBE() {
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
  void toByteArrayIntegerValueLE() {
    int byteSize = 4;

    int value = 2147483643;
    ByteBuffer byteBuffer = ByteBuffer.allocate(byteSize).order(ByteOrder.LITTLE_ENDIAN);
    byteBuffer.putInt(value);

    byte[] bytes = Bytes.toByteArrayLE(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    Assertions.assertEquals(value, byteBuffer.getInt());
  }

  @Test
  void toByteArrayIntegerArrayValueBE() {
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
  void toByteArrayIntArrayValueBEWithOffsetAndLength() {
    int byteSize = 4;

    int[] values = new int[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * values.length).order(ByteOrder.BIG_ENDIAN);
    for (int i = 0; i < values.length; i++) {
      byteBuffer.putInt(values[i]);
    }
    int offset = 5;
    int length = 5;
    byte[] bytes = Bytes.toByteArray(values, offset, length);
    byte[] buffer = byteBuffer.array();
    int index = 0;
    Assertions.assertEquals(bytes.length, length * byteSize);
    for (int i = offset; i < offset + length; i++) {
      Assertions.assertEquals(values[i], Integers.toInteger(bytes, index));
      Assertions.assertEquals(values[i], Integers.toInteger(buffer, (index + offset * byteSize)));
      index += byteSize;
    }
  }

  @Test
  void toByteArrayIntArrayValueLEWithOffsetAndLength() {
    int byteSize = 4;

    int[] values = new int[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * values.length).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < values.length; i++) {
      byteBuffer.putInt(values[i]);
    }
    int offset = 5;
    int length = 5;
    byte[] bytes = Bytes.toByteArrayLE(values, offset, length);
    byte[] buffer = byteBuffer.array();
    int index = 0;
    Assertions.assertEquals(bytes.length, length * byteSize);
    for (int i = offset; i < offset + length; i++) {
      Assertions.assertEquals(values[i], Integers.toIntegerLE(bytes, index));
      Assertions.assertEquals(values[i], Integers.toIntegerLE(buffer, (index + offset * byteSize)));
      index += byteSize;
    }
  }

  @Test
  void toByteArrayIntegerArrayValueLE() {
    int byteSize = 4;

    int[] value = new int[] {3, 2147483643};
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * value.length).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < value.length; i++) {
      byteBuffer.putInt(value[i]);
    }

    byte[] bytes = Bytes.toByteArrayLE(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < bytes.length; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    for (int i = 0; i < value.length; i++) {
      Assertions.assertEquals(value[i], byteBuffer.getInt());
    }
  }

  @Test
  void toByteArrayLongValueBE() {
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
  void toByteArrayLongValueLE() {
    int byteSize = 8;

    long value = 9223372036854775805L;
    ByteBuffer byteBuffer = ByteBuffer.allocate(byteSize).order(ByteOrder.LITTLE_ENDIAN);
    byteBuffer.putLong(value);

    byte[] bytes = Bytes.toByteArrayLE(value);
    byte[] buffer = byteBuffer.array();

    Assertions.assertEquals(bytes.length, buffer.length);
    for (int i = 0; i < byteSize; i++) {
      Assertions.assertEquals(bytes[i], buffer[i]);
    }
    byteBuffer.rewind();
    Assertions.assertEquals(value, byteBuffer.getLong());
  }

  @Test
  void toByteArrayLongArrayValueBE() {
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
  void toByteArrayLongArrayValueBEWithOffsetAndLength() {
    int byteSize = 8;

    long[] values = new long[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * values.length).order(ByteOrder.BIG_ENDIAN);
    for (int i = 0; i < values.length; i++) {
      byteBuffer.putLong(values[i]);
    }
    int offset = 5;
    int length = 5;
    byte[] bytes = Bytes.toByteArray(values, offset, length);
    byte[] buffer = byteBuffer.array();
    int index = 0;
    Assertions.assertEquals(bytes.length, length * byteSize);
    for (int i = offset; i < offset + length; i++) {
      Assertions.assertEquals(values[i], Longs.toLong(bytes, index));
      Assertions.assertEquals(values[i], Longs.toLong(buffer, (index + offset * byteSize)));
      index += byteSize;
    }
  }

  @Test
  void toByteArrayLongArrayValueLE() {
    int byteSize = 8;

    long[] value = new long[] {3L, 9223372036854775805L};
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * value.length).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < value.length; i++) {
      byteBuffer.putLong(value[i]);
    }

    byte[] bytes = Bytes.toByteArrayLE(value);
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
  void toByteArrayLongArrayValueLEWithOffsetAndLength() {
    int byteSize = 8;

    long[] values = new long[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    ByteBuffer byteBuffer =
        ByteBuffer.allocate(byteSize * values.length).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < values.length; i++) {
      byteBuffer.putLong(values[i]);
    }
    int offset = 5;
    int length = 5;
    byte[] bytes = Bytes.toByteArrayLE(values, offset, length);
    byte[] buffer = byteBuffer.array();
    int index = 0;
    Assertions.assertEquals(bytes.length, length * byteSize);
    for (int i = offset; i < offset + length; i++) {
      Assertions.assertEquals(values[i], Longs.toLongLE(bytes, index));
      Assertions.assertEquals(values[i], Longs.toLongLE(buffer, (index + offset * byteSize)));
      index += byteSize;
    }
  }
}

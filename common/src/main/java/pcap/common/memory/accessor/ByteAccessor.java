/** This code is licenced under the GPL version 2. */
package pcap.common.memory.accessor;

import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public interface ByteAccessor {

  byte[] allocate(int size);

  ByteBuffer nioBuffer(byte[] buffer, int offset, int length);

  byte getByte(byte[] buffer, int index);

  short getShort(byte[] buffer, int index);

  short getShortLE(byte[] buffer, int index);

  int getInt(byte[] buffer, int index);

  int getIntLE(byte[] buffer, int index);

  long getLong(byte[] buffer, int index);

  long getLongLE(byte[] buffer, int index);

  void getBytes(byte[] srcBuf, int index, byte[] dstBuf, int dstIndex, int size);

  void setByte(byte[] buffer, int index, int val);

  void setShort(byte[] buffer, int index, int val);

  void setShortLE(byte[] buffer, int index, int val);

  void setInt(byte[] buffer, int index, int val);

  void setIntLE(byte[] buffer, int index, int val);

  void setLong(byte[] buffer, int index, long val);

  void setLongLE(byte[] buffer, int index, long val);

  void setBytes(byte[] dstBuf, int index, byte[] srcBuf, int srcIndex, int size);
}

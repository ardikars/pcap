/** This code is licenced under the GPL version 2. */
package pcap.common.internal;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.AccessController;
import java.security.PrivilegedAction;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class Unsafe {

  public static final boolean HAS_UNSAFE = UnsafeHelper.isUnsafeAvailable();
  public static final Unsafe UNSAFE = HAS_UNSAFE ? new Unsafe() : null;

  private Unsafe() {
    if (!UnsafeHelper.isUnsafeAvailable()) {
      throw new RuntimeException("sun.misc.Unsafe is not available.");
    }
  }

  public int arrayBaseOffset(Class<?> arrayClass) {
    return UnsafeHelper.UNSAFE.arrayBaseOffset(arrayClass);
  }

  public long allocateMemory(long bytes) {
    return UnsafeHelper.UNSAFE.allocateMemory(bytes);
  }

  /**
   * Resizes a new block of native memory, to the given size in bytes. The contents of the new block
   * past the size of the old block are uninitialized; they will generally be garbage. The resulting
   * native pointer will be zero if and only if the requested size is zero. The resulting native
   * pointer will be aligned for all value types. Dispose of this memory by calling {@link
   * #freeMemory}, or resize it with {@link #reallocateMemory}. The address passed to this method
   * may be null, in which case an allocation will be performed.
   *
   * <p><em>Note:</em> It is the resposibility of the caller to make sure arguments are checked
   * before the methods are called. While some rudimentary checks are performed on the input, the
   * checks are best effort and when performance is an overriding priority, as when methods of this
   * class are optimized by the runtime compiler, some or all checks (if any) may be elided. Hence,
   * the caller must not rely on the checks and corresponding exceptions!
   *
   * @throws RuntimeException if the size is negative or too large for the native size_t type
   * @throws OutOfMemoryError if the allocation is refused by the system
   * @see #allocateMemory
   * @param address memory address.
   * @param bytes size of new memory block.
   * @return returns memory address.
   */
  public long reallocateMemory(long address, long bytes) {
    return UnsafeHelper.UNSAFE.reallocateMemory(address, bytes);
  }

  /**
   * Disposes of a block of native memory, as obtained from {@link #allocateMemory} or {@link
   * #reallocateMemory}. The address passed to this method may be null, in which case no action is
   * taken.
   *
   * <p><em>Note:</em> It is the resposibility of the caller to make sure arguments are checked
   * before the methods are called. While some rudimentary checks are performed on the input, the
   * checks are best effort and when performance is an overriding priority, as when methods of this
   * class are optimized by the runtime compiler, some or all checks (if any) may be elided. Hence,
   * the caller must not rely on the checks and corresponding exceptions!
   *
   * @throws RuntimeException if any of the arguments is invalid
   * @see #allocateMemory
   * @param address memory address.
   */
  public void freeMemory(long address) {
    UnsafeHelper.UNSAFE.freeMemory(address);
  }

  /**
   * Sets all bytes in a given block of memory to a copy of another block.
   *
   * @param srcBase src base.
   * @param srcOffset src offset.
   * @param destBase dst base.
   * @param destOffset dst offset.
   * @param bytes size.
   */
  public void copyMemory(
      Object srcBase, long srcOffset, Object destBase, long destOffset, long bytes) {
    UnsafeHelper.UNSAFE.copyMemory(srcBase, srcOffset, destBase, destOffset, bytes);
  }

  /**
   * Fetches a value from a given memory address. If the address is zero, or does not point into a
   * block obtained from {@link #allocateMemory}, the results are undefined.
   *
   * @param address memory address.
   * @see #allocateMemory
   */
  public byte getByte(long address) {
    return UnsafeHelper.UNSAFE.getByte(address);
  }

  /**
   * Fetches a value from a given memory address. If the address is zero, or does not point into a
   * block obtained from {@link #allocateMemory}, the results are undefined.
   *
   * @param object object.
   * @param address memory address.
   * @see #allocateMemory
   */
  public byte getByte(Object object, long address) {
    return UnsafeHelper.UNSAFE.getByte(object, address);
  }

  /**
   * Stores a value into a given memory address. If the address is zero, or does not point into a
   * block obtained from {@link #allocateMemory}, the results are undefined.
   *
   * @param address memory address.
   * @param x value.
   * @see #getByte(long)
   */
  public void putByte(long address, byte x) {
    UnsafeHelper.UNSAFE.putByte(address, x);
  }

  /**
   * Stores a value into a given memory address. If the address is zero, or does not point into a
   * block obtained from {@link #allocateMemory}, the results are undefined.
   *
   * @param object object.
   * @param address memory address.
   * @param x value.
   * @see #getByte(long)
   */
  public void putByte(Object object, long address, byte x) {
    UnsafeHelper.UNSAFE.putByte(object, address, x);
  }

  /**
   * @param address memory address.
   * @see #getByte(long)
   */
  public short getShort(long address) {
    return UnsafeHelper.UNSAFE.getShort(address);
  }

  /**
   * @param object object.
   * @param address memory address.
   * @see #getInt(long)
   */
  public short getShort(Object object, long address) {
    return UnsafeHelper.UNSAFE.getShort(object, address);
  }

  /**
   * @param address memory address.
   * @param x value.
   * @see #putByte(long, byte)
   */
  public void putShort(long address, short x) {
    UnsafeHelper.UNSAFE.putShort(address, x);
  }

  /**
   * @param object object.
   * @param address memory address.
   * @param x value.
   */
  public void putShort(Object object, long address, short x) {
    UnsafeHelper.UNSAFE.putShort(object, address, x);
  }

  /**
   * @param address memory address.
   * @see #getByte(long)
   */
  public char getChar(long address) {
    return UnsafeHelper.UNSAFE.getChar(address);
  }

  /**
   * @param address memory address.
   * @param x value.
   * @see #putByte(long, byte)
   */
  public void putChar(long address, char x) {
    UnsafeHelper.UNSAFE.putChar(address, x);
  }

  /**
   * @param address memory address.
   * @see #getByte(long)
   */
  public int getInt(long address) {
    return UnsafeHelper.UNSAFE.getInt(address);
  }

  /**
   * @param object object.
   * @param address memory address.
   * @see #getByte(long)
   */
  public int getInt(Object object, long address) {
    return UnsafeHelper.UNSAFE.getInt(object, address);
  }

  /**
   * @param address memory address.
   * @param x value.
   * @see #putByte(long, byte)
   */
  public void putInt(long address, int x) {
    UnsafeHelper.UNSAFE.putInt(address, x);
  }

  /**
   * @param object object.
   * @param address memory address.
   * @param x value.
   * @see #putByte(long, byte)
   */
  public void putInt(Object object, long address, int x) {
    UnsafeHelper.UNSAFE.putInt(object, address, x);
  }

  /**
   * @param address memory address.
   * @see #getByte(long)
   */
  public long getLong(long address) {
    return UnsafeHelper.UNSAFE.getLong(address);
  }

  /**
   * @param object object.
   * @param address memory address.
   * @see #getByte(long)
   */
  public long getLong(Object object, long address) {
    return UnsafeHelper.UNSAFE.getLong(object, address);
  }

  /**
   * @param address memory address.
   * @param x value.
   * @see #putByte(long, byte)
   */
  public void putLong(long address, long x) {
    UnsafeHelper.UNSAFE.putLong(address, x);
  }

  /**
   * @param object object.
   * @param address memory address.
   * @param x value.
   * @see #putByte(long, byte)
   */
  public void putLong(Object object, long address, long x) {
    UnsafeHelper.UNSAFE.putLong(object, address, x);
  }

  /**
   * @param address memory address.
   * @see #getByte(long)
   */
  public float getFloat(long address) {
    return UnsafeHelper.UNSAFE.getFloat(address);
  }

  /**
   * @param address memory address.
   * @param x value.
   * @see #putByte(long, byte)
   */
  public void putFloat(long address, float x) {
    UnsafeHelper.UNSAFE.putFloat(address, x);
  }

  /**
   * @param address memory address.
   * @see #getByte(long)
   */
  public double getDouble(long address) {
    return UnsafeHelper.UNSAFE.getDouble(address);
  }

  /**
   * @param address memory address.
   * @param x value.
   * @see #putByte(long, byte)
   */
  public void putDouble(long address, double x) {
    UnsafeHelper.UNSAFE.putDouble(address, x);
  }

  /**
   * Reports the location of a given field in the storage allocation of its class. Do not expect to
   * perform any sort of arithmetic on this offset; it is just a cookie which is passed to the
   * unsafe heap memory accessors.
   *
   * <p>Any given field will always have the same offset and base, and no two distinct fields of the
   * same class will ever have the same offset and base.
   *
   * <p>As of 1.4.1, offsets for fields are represented as long values, although the Sun JVM does
   * not use the most significant 32 bits. However, JVM implementations which store static fields at
   * absolute addresses can use long offsets and null base pointers to express the field locations
   * in a form usable by {@link #getInt(Object,long)}. Therefore, code which will be ported to such
   * JVMs on 64-bit platforms must preserve all bits of static field offsets.
   *
   * @see #getInt(Object, long)
   */
  public long objectFieldOffset(Field f) {
    return UnsafeHelper.UNSAFE.objectFieldOffset(f);
  }

  /**
   * Get direct ByteBuffer cleaner.
   *
   * @return cleaner method.
   */
  public Method bufferCleaner() {
    Method method;
    final ByteBuffer buffer = ByteBuffer.allocateDirect(1);
    Object maybeInvokeMethod =
        AccessController.doPrivileged(
            new PrivilegedAction<Object>() {
              @Override
              public Object run() {
                try {
                  // See https://bugs.openjdk.java.net/browse/JDK-8171377
                  Method m =
                      UnsafeHelper.UNSAFE
                          .getClass()
                          .getDeclaredMethod("invokeCleaner", ByteBuffer.class);
                  m.invoke(UnsafeHelper.UNSAFE, buffer);
                  return m;
                } catch (NoSuchMethodException e) {
                  return e;
                } catch (InvocationTargetException e) {
                  return e;
                } catch (IllegalAccessException e) {
                  return e;
                }
              }
            });
    if (maybeInvokeMethod instanceof Throwable) {
      method = null;
    } else {
      method = (Method) maybeInvokeMethod;
    }
    return method;
  }
}

/** This code is licenced under the GPL version 2. */
package pcap.common.internal;

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

  public int arrayBaseOffset(Class<?> arrayClass) {
    return UnsafeHelper.getUnsafe().arrayBaseOffset(arrayClass);
  }

  public long allocateMemory(long bytes) {
    return UnsafeHelper.getUnsafe().allocateMemory(bytes);
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
    return UnsafeHelper.getUnsafe().reallocateMemory(address, bytes);
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
    UnsafeHelper.getUnsafe().freeMemory(address);
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
    UnsafeHelper.getUnsafe().copyMemory(srcBase, srcOffset, destBase, destOffset, bytes);
  }

  /**
   * Fetches a value from a given memory address. If the address is zero, or does not point into a
   * block obtained from {@link #allocateMemory}, the results are undefined.
   *
   * @see #allocateMemory
   */
  public byte getByte(long address) {
    return UnsafeHelper.getUnsafe().getByte(address);
  }

  /**
   * Stores a value into a given memory address. If the address is zero, or does not point into a
   * block obtained from {@link #allocateMemory}, the results are undefined.
   *
   * @see #getByte(long)
   */
  public void putByte(long address, byte x) {
    UnsafeHelper.getUnsafe().putByte(address, x);
  }

  /** @see #getByte(long) */
  public short getShort(long address) {
    return UnsafeHelper.getUnsafe().getShort(address);
  }

  /** @see #putByte(long, byte) */
  public void putShort(long address, short x) {
    UnsafeHelper.getUnsafe().putShort(address, x);
  }

  /** @see #getByte(long) */
  public char getChar(long address) {
    return UnsafeHelper.getUnsafe().getChar(address);
  }

  /** @see #putByte(long, byte) */
  public void putChar(long address, char x) {
    UnsafeHelper.getUnsafe().putChar(address, x);
  }

  /** @see #getByte(long) */
  public int getInt(long address) {
    return UnsafeHelper.getUnsafe().getInt(address);
  }

  /** @see #putByte(long, byte) */
  public void putInt(long address, int x) {
    UnsafeHelper.getUnsafe().putInt(address, x);
  }

  /** @see #getByte(long) */
  public long getLong(long address) {
    return UnsafeHelper.getUnsafe().getLong(address);
  }

  /** @see #putByte(long, byte) */
  public void putLong(long address, long x) {
    UnsafeHelper.getUnsafe().putLong(address, x);
  }

  /** @see #getByte(long) */
  public float getFloat(long address) {
    return UnsafeHelper.getUnsafe().getFloat(address);
  }

  /** @see #putByte(long, byte) */
  public void putFloat(long address, float x) {
    UnsafeHelper.getUnsafe().putFloat(address, x);
  }

  /** @see #getByte(long) */
  public double getDouble(long address) {
    return UnsafeHelper.getUnsafe().getDouble(address);
  }

  /** @see #putByte(long, byte) */
  public void putDouble(long address, double x) {
    UnsafeHelper.getUnsafe().putDouble(address, x);
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
                      UnsafeHelper.getUnsafe()
                          .getClass()
                          .getDeclaredMethod("invokeCleaner", ByteBuffer.class);
                  m.invoke(UnsafeHelper.getUnsafe(), buffer);
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

/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.util.Collections;
import pcap.spi.Selectable;
import pcap.spi.Selector;
import pcap.spi.Timeout;
import pcap.spi.exception.TimeoutException;

class DefaultWaitForMultipleObjectsSelector extends AbstractSelector<NativeMappings.HANDLE> {

  private static final int EINTR = 4;

  private NativeMappings.HANDLE[] handles = new NativeMappings.HANDLE[0];

  DefaultWaitForMultipleObjectsSelector() {
    super.isClosed = false;
  }

  @Override
  public Iterable<Selectable> select(Timeout timeout) throws TimeoutException {
    validateSelect(timeout);
    int ts = (int) timeout.microSecond() / 1000;
    int rc;
    do {
      rc = Kernel32.INSTANCE.WaitForMultipleObjects(registered.size(), handles, false, ts);
    } while (rc < 0 && EINTR == Native.getLastError());
    return toIterable(rc, ts);
  }

  Iterable<Selectable> toIterable(int rc, int timeout) throws TimeoutException {
    if (rc < 0 || rc >= registered.size()) {
      if (rc == 0x00000102) {
        throw new TimeoutException("Timeout: " + timeout + " ms.");
      }
      return Collections.EMPTY_LIST;
    }
    return new SelectableList<Selectable>(registered.get(handles[rc]));
  }

  @Override
  public Selector register(Selectable pcap) {
    DefaultPcap defaultPcap = validateRegister(pcap);
    if (!registered.isEmpty()) {
      // register new pcap
      NativeMappings.HANDLE[] newHandles = add(defaultPcap, handles.length + 1);
      System.arraycopy(handles, 0, newHandles, 0, handles.length);
      this.handles = newHandles;
    } else {
      this.handles = add(defaultPcap, 1);
    }
    return this;
  }

  private NativeMappings.HANDLE[] add(DefaultPcap pcap, int size) {
    NativeMappings.HANDLE[] newHandles = new NativeMappings.HANDLE[size];
    NativeMappings.HANDLE handle = NativeMappings.PLATFORM_DEPENDENT.pcap_getevent(pcap.pointer);
    newHandles[handles.length] = handle;
    pcap.selector = this;
    registered.put(handle, pcap);
    return newHandles;
  }

  @Override
  protected void cancel(DefaultPcap pcap) {
    NativeMappings.HANDLE handle = NativeMappings.PLATFORM_DEPENDENT.pcap_getevent(pcap.pointer);
    for (int i = 0; i < registered.size(); i++) {
      if (Pointer.nativeValue(handle.getPointer())
          == Pointer.nativeValue(handles[i].getPointer())) {
        NativeMappings.HANDLE[] newHandles = new NativeMappings.HANDLE[handles.length - 1];
        int index = 0;
        for (int j = 0; j < handles.length; j++) {
          if (j != i) {
            newHandles[index] = handles[index];
            index++;
          } else {
            registered.remove(handle);
          }
        }
        break;
      }
    }
  }

  public interface Kernel32 extends Library {

    Kernel32 INSTANCE = Native.load("kernel32", Kernel32.class);

    int WaitForMultipleObjects(
        int nCount, NativeMappings.HANDLE[] hHandle, boolean bWaitAll, int dwMilliseconds);
  }
}

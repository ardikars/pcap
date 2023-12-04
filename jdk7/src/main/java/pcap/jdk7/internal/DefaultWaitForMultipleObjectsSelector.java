/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.util.Collections;
import java.util.Iterator;
import pcap.spi.Selectable;
import pcap.spi.Selection;
import pcap.spi.Selector;
import pcap.spi.Timeout;
import pcap.spi.exception.NoSuchSelectableException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.util.Consumer;

class DefaultWaitForMultipleObjectsSelector extends AbstractSelector<NativeMappings.HANDLE> {

  private static final int EINTR = 4;

  private NativeMappings.HANDLE[] handles = new NativeMappings.HANDLE[0];

  DefaultWaitForMultipleObjectsSelector() {
    super.isClosed = false;
  }

  Iterable<Selectable> toIterableSelectable(int rc, int timeout) throws TimeoutException {
    if (rc == 0x00000102) {
      throw new TimeoutException(String.format("Timeout: %d ms.", timeout));
    }
    if (rc < 0) {
      return Collections.emptyList();
    }
    final DefaultSelection selection = registered.get(handles[rc]);
    selection.setReadyOperation(selection.interestOperations());
    return new SelectableList<Selectable>(selection.pcap);
  }

  private NativeMappings.HANDLE[] add(DefaultSelection selection, int size) {
    NativeMappings.HANDLE[] newHandles = new NativeMappings.HANDLE[size];
    NativeMappings.HANDLE handle =
        NativeMappings.PLATFORM_DEPENDENT.pcap_getevent(selection.pcap.pointer);
    newHandles[handles.length] = handle;
    selection.pcap.selector = this;
    registered.put(handle, selection);
    return newHandles;
  }

  @Override
  public Selector register(Selectable pcap) throws IllegalArgumentException, IllegalStateException {
    register(pcap, Selection.OPERATION_READ, null);
    return this;
  }

  @Override
  Selection register(Selectable selectable, int interestOperations, Object attachment)
      throws IllegalArgumentException, IllegalStateException {
    checkOpenState();
    DefaultSelection selection = validateRegister(selectable, attachment);
    if (!registered.isEmpty()) {
      // register new pcap
      NativeMappings.HANDLE[] newHandles = add(selection, handles.length + 1);
      System.arraycopy(handles, 0, newHandles, 0, handles.length);
      this.handles = newHandles;
    } else {
      this.handles = add(selection, 1);
    }
    selection.interestOperations(interestOperations);
    selection.attach(attachment);
    return selection;
  }

  @Override
  void interestOperations(DefaultSelection selection, int interestOperations) {
    checkOpenState();
    selection.interestOperations(interestOperations);
  }

  @Override
  public Iterable<Selectable> select(Timeout timeout)
      throws TimeoutException,
          NoSuchSelectableException,
          IllegalStateException,
          IllegalArgumentException {
    checkOpenState();
    validateSelect(timeout);
    int ts = (int) timeout.microSecond() / 1000;
    int rc;
    do {
      rc = Kernel32.INSTANCE.WaitForMultipleObjects(registered.size(), handles, false, ts);
    } while (rc < 0 && EINTR == Native.getLastError());
    return toIterableSelectable(rc, ts);
  }

  @Override
  public int select(Consumer<Selection> consumer, Timeout timeout)
      throws TimeoutException,
          NoSuchSelectableException,
          IllegalStateException,
          IllegalArgumentException {
    checkOpenState();
    validateSelect(timeout);
    int ts = (int) timeout.microSecond() / 1000;
    int rc;
    do {
      rc = Kernel32.INSTANCE.WaitForMultipleObjects(registered.size(), handles, false, ts);
    } while (rc < 0 && EINTR == Native.getLastError());
    return callback(rc, timeout, consumer);
  }

  int callback(int rc, Timeout timeout, Consumer<Selection> consumer) throws TimeoutException {
    if (rc == 0x00000102) {
      throw new TimeoutException(String.format("Timeout: %s ms.", timeout));
    }
    if (rc < 0) {
      return 0;
    }
    final DefaultSelection selection = registered.get(handles[rc]);
    selection.setReadyOperation(selection.interestOperations());
    consumer.accept(selection);
    return 1;
  }

  @Override
  protected void cancel(DefaultPcap pcap) {
    checkOpenState();
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

  @Override
  public void close() {
    checkOpenState();
    Iterator<DefaultSelection> iterator = registered.values().iterator();
    while (iterator.hasNext()) {
      iterator.next().pcap.selector = null;
      iterator.remove();
    }
    isClosed = true;
  }

  public interface Kernel32 extends Library {

    Kernel32 INSTANCE = Native.load("kernel32", Kernel32.class);

    int WaitForMultipleObjects(
        int nCount, NativeMappings.HANDLE[] hHandle, boolean bWaitAll, int dwMilliseconds);
  }
}

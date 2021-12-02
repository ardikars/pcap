/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.util.HashMap;
import java.util.Map;
import pcap.spi.Selectable;
import pcap.spi.Selection;
import pcap.spi.Selector;
import pcap.spi.Timeout;
import pcap.spi.exception.NoSuchSelectableException;

abstract class AbstractSelector<T> implements Selector {

  protected final Map<T, DefaultSelection> registered = new HashMap<T, DefaultSelection>();

  protected boolean isClosed;

  abstract Selection register(Selectable selectable, int interestOperations, Object attachment)
      throws IllegalArgumentException, IllegalStateException;

  abstract void interestOperations(DefaultSelection selection, int interestOperations);

  abstract void cancel(DefaultPcap pcap);

  protected void validateSelect(Timeout timeout) {
    if (isClosed) {
      throw new IllegalStateException("Selector is closed.");
    }
    if (registered.isEmpty()) {
      throw new NoSuchSelectableException(
          "No such \"selectable\" has been registered on this selector.");
    }
    if (timeout == null || timeout.microSecond() < 1000) {
      throw new IllegalArgumentException(
          String.format(
              "timeout: %s (expected: timeout != null && timeout >= 1000 microseconds).", timeout));
    }
  }

  protected void checkOpenState() {
    if (isClosed) {
      throw new IllegalStateException("Selector is closed.");
    }
  }

  protected DefaultSelection validateRegister(Selectable pcap, Object attachment) {
    if (isClosed) {
      throw new IllegalStateException("Selector is closed.");
    }
    Utils.requireNonNull(pcap, "selectable: null (expected: selectable != null).");
    if (!(pcap instanceof DefaultPcap)) {
      throw new IllegalArgumentException(pcap.getClass().getSimpleName() + " is not supperted.");
    }
    DefaultPcap defaultPcap = (DefaultPcap) pcap;
    if (defaultPcap.selector != null) {
      throw new IllegalArgumentException(
          "Selectable is already registered on this or another selector.");
    }
    if (defaultPcap.netmask == 0) {
      throw new IllegalArgumentException("Offline selectable is not supported.");
    }
    return new DefaultSelection(this, defaultPcap, attachment);
  }
}

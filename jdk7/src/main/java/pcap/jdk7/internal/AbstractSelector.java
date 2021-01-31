/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import pcap.spi.Selectable;
import pcap.spi.Selector;

abstract class AbstractSelector<T> implements Selector {

  protected final Map<T, DefaultPcap> registered = new HashMap<T, DefaultPcap>();

  abstract void cancel(DefaultPcap pcap);

  @Override
  public void close() throws Exception {
    Iterator<DefaultPcap> iterator = registered.values().iterator();
    while (iterator.hasNext()) {
      iterator.next().selector = null;
      iterator.remove();
    }
  }

  protected DefaultPcap validate(Selectable pcap) {
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
    return defaultPcap;
  }
}

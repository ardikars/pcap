/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.util.HashMap;
import java.util.Map;
import pcap.spi.Selector;

abstract class AbstractSelector<T> implements Selector {

  protected final Map<T, DefaultPcap> registered = new HashMap<T, DefaultPcap>();

  abstract void cancel(DefaultPcap pcap);
}

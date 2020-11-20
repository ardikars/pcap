/*
 * Copyright (c) 2020 Pcap <contact@pcap.ardikars.com>
 * SPDX-License-Identifier: MIT
 */
package pcap.jdk7.internal;

import java.util.Iterator;
import java.util.NoSuchElementException;
import pcap.spi.Address;

class DefaultAddressIterator implements Iterator<Address> {

  private Address next;

  DefaultAddressIterator(Address next) {
    this.next = next;
  }

  @Override
  public boolean hasNext() {
    return next != null;
  }

  @Override
  public Address next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }
    Address previous = next;
    next = next.next();
    return previous;
  }

  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }
}

/*
 * Copyright (c) 2020-2022 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.util.Iterator;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import pcap.spi.Selectable;
import pcap.spi.Selection;
import pcap.spi.Selector;

class SelectableListTest {

  @Test
  void add() {
    SelectableImpl selectable1 = new SelectableImpl();
    SelectableImpl selectable2 = new SelectableImpl();
    SelectableList<SelectableImpl> selectables1 = new SelectableList<>();
    selectables1.add(selectable1);
    selectables1.add(selectable2);
    final Iterator<SelectableImpl> iterator1 = selectables1.iterator();
    while (iterator1.hasNext()) {
      SelectableImpl next = iterator1.next();
      Assertions.assertNotNull(next);
    }
    Assertions.assertThrows(
        NoSuchElementException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            iterator1.next();
          }
        });
    Assertions.assertThrows(
        UnsupportedOperationException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            iterator1.remove();
          }
        });
    SelectableList<SelectableImpl> selectables2 = new SelectableList<>(selectable1);
    selectables2.add(selectable2);
    final Iterator<SelectableImpl> iterator2 = selectables2.iterator();
    while (iterator2.hasNext()) {
      SelectableImpl next = iterator2.next();
      Assertions.assertNotNull(next);
    }
    Assertions.assertThrows(
        NoSuchElementException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            iterator2.next();
          }
        });
    Assertions.assertThrows(
        UnsupportedOperationException.class,
        new Executable() {
          @Override
          public void execute() throws Throwable {
            iterator2.remove();
          }
        });
  }

  static final class SelectableImpl implements Selectable {

    @Override
    public Object id() {
      return null;
    }

    @Override
    public void close() {}

    @Override
    public Selection register(Selector selector, int interestOperations, Object attachment)
        throws IllegalArgumentException, IllegalStateException {
      return null;
    }
  }
}

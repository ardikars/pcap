/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Selectable list.
 *
 * @param <T> selectable type.
 * @since 1.1.0
 */
class SelectableList<T> implements Iterable<T> {

  Node<T> head;

  /**
   * No selectable data.
   *
   * @since 1.1.0
   */
  public SelectableList() {
    this.head = null;
  }

  /**
   * Add single selectable data.
   *
   * @param initial initial head.
   * @since 1.1.0
   */
  public SelectableList(T initial) {
    add(initial);
  }

  /**
   * Add selectable data.
   *
   * @param data selectable.
   * @since 1.1.0
   */
  public void add(T data) {
    Node<T> newNode = new Node<T>();
    newNode.data = data;
    newNode.next = head;
    this.head = newNode;
  }

  @Override
  public Iterator<T> iterator() {
    return new SelectableListIterator<T>(head);
  }

  private static final class Node<T> {
    private T data;
    private Node<T> next;
  }

  private static final class SelectableListIterator<T> implements Iterator<T> {

    private Node<T> node;

    private SelectableListIterator(Node<T> node) {
      this.node = node;
    }

    @Override
    public boolean hasNext() {
      return node != null;
    }

    @Override
    public T next() {
      if (!hasNext()) {
        throw new NoSuchElementException();
      }
      Node<T> previous = node;
      this.node = node.next;
      return previous.data;
    }

    @Override
    public void remove() {
      throw new UnsupportedOperationException();
    }
  }
}

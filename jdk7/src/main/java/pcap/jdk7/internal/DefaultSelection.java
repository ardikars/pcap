/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import pcap.spi.Selectable;
import pcap.spi.Selection;
import pcap.spi.Selector;

/**
 * Default selection key.
 *
 * @since 1.4.0
 */
class DefaultSelection implements Selection {

  private static final AtomicReferenceFieldUpdater<DefaultSelection, Object> ATTACHMENT =
      AtomicReferenceFieldUpdater.newUpdater(DefaultSelection.class, Object.class, "attachment");

  private static final AtomicIntegerFieldUpdater<DefaultSelection> READY_OPERATIONS =
      AtomicIntegerFieldUpdater.newUpdater(DefaultSelection.class, "readyOperations");

  private static final AtomicIntegerFieldUpdater<DefaultSelection> INTEREST_OPERATIONS =
      AtomicIntegerFieldUpdater.newUpdater(DefaultSelection.class, "interestOperations");

  final AbstractSelector<?> abstractSelector;
  final DefaultPcap pcap;
  int pollFDsIndex; // only for poll
  private volatile int readyOperations;
  private volatile int interestOperations;

  @SuppressWarnings("all")
  private volatile Object attachment;

  DefaultSelection(AbstractSelector<?> abstractSelector, DefaultPcap pcap, Object attachment) {
    this.abstractSelector = abstractSelector;
    this.pcap = pcap;
    this.attachment = attachment;
  }

  @Override
  public Selection attach(Object attachment) {
    ATTACHMENT.getAndSet(this, attachment);
    return this;
  }

  @Override
  public Object attachment() {
    return attachment;
  }

  @Override
  public int readyOperations() {
    return readyOperations;
  }

  @Override
  public boolean isReadable() {
    return (readyOperations() & OPERATION_READ) != 0;
  }

  @Override
  public boolean isWritable() {
    return (readyOperations() & OPERATION_WRITE) != 0;
  }

  @Override
  public int interestOperations() {
    return interestOperations;
  }

  @Override
  public Selection interestOperations(int interestOperations) {
    validateOperations(interestOperations);
    int oldOps = INTEREST_OPERATIONS.getAndSet(this, interestOperations);
    if (oldOps != interestOperations) {
      abstractSelector.interestOperations(this, interestOperations);
    }
    return this;
  }

  @Override
  public Selector selector() {
    return abstractSelector;
  }

  @Override
  public Selectable selectable() {
    return pcap;
  }

  @Override
  public void cancel() {
    abstractSelector.cancel(pcap);
  }

  @Override
  public int hashCode() {
    return pcap.hashCode();
  }

  @Override
  public boolean equals(Object o) {
    if (o == null) {
      return false;
    }
    if (!(o instanceof DefaultSelection)) {
      return false;
    }
    DefaultSelection that = (DefaultSelection) o;
    return pcap.hashCode() == that.hashCode();
  }

  void setReadyOperation(int readyOps) {
    int oldOps = READY_OPERATIONS.getAndSet(this, readyOps);
    if (oldOps != readyOps) {
      // ok
    }
  }

  static void validateOperations(int ops) {
    if ((ops & ~(Selection.OPERATION_READ | Selection.OPERATION_WRITE)) != 0) {
      throw new IllegalArgumentException("Unsupported interest operations.");
    }
  }
}

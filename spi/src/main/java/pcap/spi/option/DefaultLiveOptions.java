/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi.option;

import pcap.spi.Service;
import pcap.spi.Timestamp;
import pcap.spi.annotation.Version;

/**
 * {@inheritDoc}
 *
 * @since 1.0.0
 */
public class DefaultLiveOptions implements Service.LiveOptions {

  private int snapshotLength;
  private boolean promiscuous;
  private boolean rfmon;
  private int timeout;
  private Timestamp.Type timestampType;
  private boolean immediate;
  private int bufferSize;
  private Timestamp.Precision timestampPrecision;

  public DefaultLiveOptions() {
    this.snapshotLength = 0xFFFF;
    this.promiscuous = true;
    this.rfmon = false;
    this.timeout = 2000;
    this.timestampType = null;
    this.immediate = true;
    this.bufferSize = 0;
    this.timestampPrecision = null;
  }

  /** {@inheritDoc} */
  @Override
  public int snapshotLength() {
    return snapshotLength;
  }

  /** {@inheritDoc} */
  @Override
  public Service.LiveOptions snapshotLength(int snapshotLength) {
    this.snapshotLength = snapshotLength;
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isPromiscuous() {
    return promiscuous;
  }

  /** {@inheritDoc} */
  @Override
  public Service.LiveOptions promiscuous(boolean promiscuous) {
    this.promiscuous = promiscuous;
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isRfmon() {
    return rfmon;
  }

  /** {@inheritDoc} */
  @Override
  public Service.LiveOptions rfmon(boolean rfmon) {
    this.rfmon = rfmon;
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public int timeout() {
    return timeout;
  }

  /** {@inheritDoc} */
  @Override
  public Service.LiveOptions timeout(int timeout) {
    this.timeout = timeout;
    return this;
  }

  /** {@inheritDoc} */
  @Version(major = 1, minor = 2, patch = 1)
  @Override
  public Timestamp.Type timestampType() {
    return timestampType;
  }

  /** {@inheritDoc} */
  @Version(major = 1, minor = 2, patch = 1)
  @Override
  public Service.LiveOptions timestampType(Timestamp.Type timestampType) {
    this.timestampType = timestampType;
    return this;
  }

  /** {@inheritDoc} */
  @Version(major = 1, minor = 5, patch = 0)
  @Override
  public boolean isImmediate() {
    return immediate;
  }

  /** {@inheritDoc} */
  @Version(major = 1, minor = 5, patch = 0)
  @Override
  public Service.LiveOptions immediate(boolean immediate) {
    this.immediate = immediate;
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public int bufferSize() {
    return bufferSize;
  }

  /** {@inheritDoc} */
  @Override
  public Service.LiveOptions bufferSize(int bufferSize) {
    this.bufferSize = bufferSize;
    return this;
  }

  /** {@inheritDoc} */
  @Version(major = 1, minor = 5, patch = 0)
  @Override
  public Timestamp.Precision timestampPrecision() {
    return timestampPrecision;
  }

  /** {@inheritDoc} */
  @Version(major = 1, minor = 5, patch = 0)
  @Override
  public Service.LiveOptions timestampPrecision(Timestamp.Precision timestampPrecision) {
    this.timestampPrecision = timestampPrecision;
    return this;
  }
}

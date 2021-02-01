/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import pcap.spi.Selectable;
import pcap.spi.Selector;
import pcap.spi.Timeout;
import pcap.spi.exception.TimeoutException;

class DefaultPollSelector extends AbstractSelector<Integer> {

  static final int POLLIN = 1;

  static final int EINTR = 4;

  pollfd[] pfds = new pollfd[0];

  DefaultPollSelector() {
    super.isClosed = false;
  }

  @Override
  public Iterable<Selectable> select(Timeout timeout) throws TimeoutException {
    validateSelect(timeout);
    int ts = (int) timeout.microSecond() / 1000;
    int rc;
    do {
      rc = LibC.INSTANCE.poll(pfds, registered.size(), ts);
    } while (doWhile(rc, Native.getLastError()));
    return toIterable(rc, ts);
  }

  boolean doWhile(int rc, int lastError) {
    return rc < 0 && EINTR == lastError;
  }

  @Override
  public Selector register(Selectable pcap) {
    DefaultPcap defaultPcap = validateRegister(pcap);
    if (!registered.isEmpty()) {
      // register new pcap
      pollfd[] newPfds = add(defaultPcap, pfds.length + 1);
      for (int i = 0; i < pfds.length; i++) {
        newPfds[i].fd = pfds[i].fd;
        newPfds[i].events = pfds[i].events;
        newPfds[i].revents = pfds[i].revents;
        newPfds[i].write();
      }
      this.pfds = newPfds;
    } else {
      this.pfds = add(defaultPcap, 1);
    }
    return this;
  }

  Iterable<Selectable> toIterable(int rc, int timeout) throws TimeoutException {
    if (rc < 0 || rc > registered.size()) {
      return Collections.EMPTY_LIST;
    }
    if (rc == 0) {
      throw new TimeoutException("Timeout: " + timeout + ".");
    }
    final SelectableList<Selectable> selected = new SelectableList<Selectable>();
    for (int i = 0; i < registered.size(); i++) {
      pfds[i].read();
      addToList(pfds[i].fd, pfds[i].revents, selected);
    }
    return selected;
  }

  void addToList(int fd, int rEvents, SelectableList<Selectable> selected) {
    if ((rEvents & POLLIN) != 0) {
      selected.add(registered.get(fd));
    }
  }

  private pollfd[] add(DefaultPcap pcap, int size) {
    pollfd[] newPfds = (pollfd[]) (new pollfd().toArray(size));
    int fd = NativeMappings.PLATFORM_DEPENDENT.pcap_get_selectable_fd(pcap.pointer);
    newPfds[pfds.length].fd = fd;
    newPfds[pfds.length].events = POLLIN;
    newPfds[pfds.length].revents = 0;
    newPfds[pfds.length].write();
    pcap.selector = this;
    registered.put(fd, pcap);
    return newPfds;
  }

  @Override
  protected void cancel(DefaultPcap pcap) {
    int fd = NativeMappings.PLATFORM_DEPENDENT.pcap_get_selectable_fd(pcap.pointer);
    for (int i = 0; i < registered.size(); i++) {
      if (pfds[i].fd == fd) {
        if (pfds.length > 1) {
          pollfd[] newPfds = (pollfd[]) (new pollfd().toArray(pfds.length - 1));
          int index = 0;
          for (int j = 0; j < pfds.length; j++) {
            if (j != i) {
              newPfds[index].fd = pfds[index].fd;
              newPfds[index].events = pfds[index].events;
              newPfds[index].revents = pfds[index].revents;
              index++;
            } else {
              registered.remove(fd);
            }
          }
        } else {
          registered.remove(fd);
        }
        break;
      }
    }
  }

  interface LibC extends Library {

    LibC INSTANCE = Native.load(Platform.C_LIBRARY_NAME, LibC.class);

    int poll(pollfd[] fds, int nfds, int timeout);
  }

  public static class pollfd extends Structure {

    public int fd;
    public short events;
    public short revents;

    public pollfd() {}

    @Override
    protected List getFieldOrder() {
      return Arrays.asList( //
          "fd", //
          "events", //
          "revents" //
          );
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      pollfd pollfd = (pollfd) o;
      return fd == pollfd.fd;
    }

    @Override
    public int hashCode() {
      return Objects.hash(fd);
    }
  }
}

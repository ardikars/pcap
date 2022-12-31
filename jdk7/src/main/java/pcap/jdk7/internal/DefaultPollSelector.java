/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Structure;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import pcap.spi.Selectable;
import pcap.spi.Selection;
import pcap.spi.Selector;
import pcap.spi.Timeout;
import pcap.spi.exception.NoSuchSelectableException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.util.Consumer;

class DefaultPollSelector extends AbstractSelector<Integer> {

  static final int POLLIN = 1;
  static final int POLLOUT = 4;

  static final int EINTR = 4;

  pollfd[] pfds = new pollfd[0];

  DefaultPollSelector() {
    super.isClosed = false;
  }

  static int toJavaEvent(int epollOps, int javaIOps) {
    int ops = 0;
    if (epollOps == POLLIN) {
      ops |= javaIOps & (Selection.OPERATION_READ);
    }
    if (epollOps == POLLOUT) {
      ops |= javaIOps & (Selection.OPERATION_WRITE);
    }
    return ops;
  }

  static short toPollEvent(int ops) {
    short eventOps = 0;
    if ((ops & (Selection.OPERATION_READ)) != 0) {
      eventOps |= POLLIN;
    }
    if ((ops & (Selection.OPERATION_WRITE)) != 0) {
      eventOps |= POLLOUT;
    }
    return eventOps;
  }

  boolean doWhile(int rc, int lastError) {
    return rc < 0 && EINTR == lastError;
  }

  Iterable<Selectable> toIterableSelectable(int rc, int timeout) throws TimeoutException {
    if (rc < 0 || rc > registered.size()) {
      return Collections.emptyList();
    }
    if (rc == 0) {
      throw new TimeoutException(String.format("Timeout: %d.", timeout));
    }
    final SelectableList<Selectable> selected = new SelectableList<Selectable>();
    for (int i = 0; i < registered.size(); i++) {
      pfds[i].read();
      final DefaultSelection selection = registered.get(pfds[i].fd);
      selection.setReadyOperation(toJavaEvent(pfds[i].revents, selection.interestOperations()));
      if (selection.isReadable()) {
        selected.add(selection.selectable());
      }
    }
    return selected;
  }

  private pollfd[] add(DefaultSelection selection, int size) {
    try {
      int fd = NativeMappings.PLATFORM_DEPENDENT.pcap_get_selectable_fd(selection.pcap.pointer);
      pollfd[] newPfds = (pollfd[]) (new pollfd().toArray(size));
      newPfds[pfds.length].fd = fd;
      newPfds[pfds.length].events = POLLIN;
      newPfds[pfds.length].revents = 0;
      newPfds[pfds.length].write();
      selection.pcap.selector = this;
      selection.pollFDsIndex = pfds.length;
      registered.put(fd, selection);
      return newPfds;
    } catch (NullPointerException | UnsatisfiedLinkError e) {
      return pfds;
    }
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
      pollfd[] newPfds = add(selection, pfds.length + 1);
      for (int i = 0; i < pfds.length; i++) {
        newPfds[i].fd = pfds[i].fd;
        newPfds[i].events = pfds[i].events;
        newPfds[i].revents = pfds[i].revents;
        newPfds[i].write();
      }
      this.pfds = newPfds;
    } else {
      this.pfds = add(selection, 1);
    }
    selection.interestOperations(interestOperations);
    selection.attach(attachment);
    return selection;
  }

  @Override
  void interestOperations(DefaultSelection selection, int interestOperations) {
    checkOpenState();
    if (pfds[selection.pollFDsIndex] != null) {
      pfds[selection.pollFDsIndex].events = toPollEvent(interestOperations);
      pfds[selection.pollFDsIndex].write();
    }
  }

  @Override
  public Iterable<Selectable> select(Timeout timeout)
      throws TimeoutException, NoSuchSelectableException, IllegalStateException,
          IllegalArgumentException {
    checkOpenState();
    validateSelect(timeout);
    int ts = (int) timeout.microSecond() / 1000;
    int rc;
    do {
      rc = LibC.INSTANCE.poll(pfds, registered.size(), ts);
    } while (doWhile(rc, Native.getLastError()));
    return toIterableSelectable(rc, ts);
  }

  @Override
  public int select(Consumer<Selection> consumer, Timeout timeout)
      throws TimeoutException, NoSuchSelectableException, IllegalStateException,
          IllegalArgumentException {
    checkOpenState();
    validateSelect(timeout);
    int ts = (int) timeout.microSecond() / 1000;
    int rc;
    do {
      rc = LibC.INSTANCE.poll(pfds, registered.size(), ts);
    } while (doWhile(rc, Native.getLastError()));
    return consume(rc, timeout, consumer);
  }

  int consume(int rc, Timeout timeout, Consumer<Selection> consumer) throws TimeoutException {
    if (rc < 0) {
      return rc;
    }
    if (rc == 0) {
      throw new TimeoutException(String.format("Timeout: %s,", timeout));
    }
    for (int i = 0; i < registered.size(); i++) {
      pfds[i].read();
      final DefaultSelection selection = registered.get(pfds[i].fd);
      selection.setReadyOperation(toJavaEvent(pfds[i].revents, selection.interestOperations()));
      consumer.accept(selection);
    }
    return rc;
  }

  @Override
  protected void cancel(DefaultPcap pcap) {
    checkOpenState();
    try {
      int fd = NativeMappings.PLATFORM_DEPENDENT.pcap_get_selectable_fd(pcap.pointer);
      for (int i = 0; i < registered.size(); i++) {
        if (pfds[i].fd == fd) {
          final pollfd[] newPfds =
              pfds.length == 1 ? null : (pollfd[]) (new pollfd().toArray(pfds.length - 1));
          if (newPfds != null) {
            int index = 0;
            for (int j = 0; j < pfds.length; j++) {
              if (j != i) {
                newPfds[index].fd = pfds[j].fd;
                newPfds[index].events = pfds[j].events;
                newPfds[index].revents = pfds[j].revents;
                index++;
              } else {
                registered.remove(fd);
              }
            }
            this.pfds = newPfds;
          } else {
            registered.remove(fd);
            this.pfds = newPfds;
          }
          break;
        }
      }
    } catch (NullPointerException | UnsatisfiedLinkError e) {
      //
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

  interface LibC extends Library {

    LibC INSTANCE = Native.load(Platform.C_LIBRARY_NAME, LibC.class);

    int poll(pollfd[] fds, int nfds, int timeout);
  }

  public static class pollfd extends Structure {

    public int fd;
    public short events;
    public short revents;

    public pollfd() {
      // public constructor
    }

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
      if (o == null) {
        return false;
      }
      if (!(o instanceof pollfd)) {
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

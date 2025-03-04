/*
 * Copyright (c) 2020-2025 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import pcap.spi.Address;
import pcap.spi.Interface;

import java.net.InetAddress;
import java.util.Iterator;

class PcapInterface implements Interface {
    static class PcapAddress implements Address {
        private Address next;
        private final InetAddress address;
        private final InetAddress netmask;
        private final InetAddress broadcast;
        private final InetAddress destination;

        public PcapAddress() {
            address = null;
            netmask = null;
            broadcast = null;
            destination = null;
        }

        public PcapAddress(InetAddress address, InetAddress netmask, InetAddress broadcast, InetAddress destination) {
            this.address = address;
            this.netmask = netmask;
            this.broadcast = broadcast;
            this.destination = destination;
        }

        public void setNext(Address next) {
            this.next = next;
        }

        @Override
        public Address next() {
            return next;
        }

        @Override
        public InetAddress address() {
            return address;
        }

        @Override
        public InetAddress netmask() {
            return netmask;
        }

        @Override
        public InetAddress broadcast() {
            return broadcast;
        }

        @Override
        public InetAddress destination() {
            return destination;
        }

        @Override
        public Iterator<Address> iterator() {
            return new DefaultAddressIterator(this);
        }
    }

    public static class NoAddress extends PcapAddress {
        @Override
        public Iterator<Address> iterator() {
            return new DefaultAddressIterator(null);
        }
    }

    public static class NoInterface extends PcapInterface {
        @Override
        public Iterator<Interface> iterator() {
            return new DefaultInterfaceIterator(null);
        }
    }
    private Interface next;
    private final String name;
    private final String description;
    private final Address address;
    private final int flags;

    public PcapInterface() {
        name = "";
        description = "";
        address = new NoAddress();
        flags = 0;
    }

    public PcapInterface(String name, String description, Address address, int flags) {
        this.name = name;
        this.description = description;
        this.address = address;
        this.flags = flags;
    }

    public void setNext(Interface next) {
        this.next = next;
    }

    @Override
    public Interface next() {
        return next;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String description() {
        return description;
    }

    @Override
    public Address addresses() {
        return address;
    }

    @Override
    public int flags() {
        return flags;
    }

    @Override
    public Iterator<Interface> iterator() {
        return new DefaultInterfaceIterator(this);
    }
}

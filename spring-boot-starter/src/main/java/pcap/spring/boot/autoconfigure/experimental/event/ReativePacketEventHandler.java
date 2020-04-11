package pcap.spring.boot.autoconfigure.experimental.event;

import pcap.spring.boot.autoconfigure.experimental.reactive.ReactivePacket;

public interface ReativePacketEventHandler<T> extends EventHandler<ReactivePacket<T>> {}

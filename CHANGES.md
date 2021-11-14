<!--
SPDX-FileCopyrightText: 2020-2021 Pcap Project
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Changelog

All notable changes to this project will be documented in this file.



## [Unreleased]

### Changed

- Use String::format(..) instead of concatenate with +

- Use common logging instead of jdk logger

- Use Arrays.asList(..) insetead new ArrayList(..) for getFieldOrders() 


### Fixed

- Fix Slf4j module name



## [1.3.3] - 2021-10-23

### Changed

- Remove incubating annotation for equals and hashCode (Fixed: force non-readable buffer to return false).



## [1.3.2] - 2021-10-22

### Changed

- Use String#compareTo instead of String#equals for creating Service.

- Remove incubating annotation on restricted methods.


### Fixed

- Fix IPv4 TTL.

- Fix IPv4 checksum offset ([#149](https://github.com/ardikars/pcap/issues/149))



## [1.3.1] - 2021-05-22

### Added

* Add optional properties for character encoding when initializing library.

* Add missing NULL/Loopback datalink type.

* Add missing Sll datalink type.

* Add @Restricted annotation (incubating).

* Add restricted method such as PacketBuffer.memoryAddress and Selectable.id() annotated with @Restricted (incubating).

* Add pcap interface flags.

* Enhance Selector, reduce object creation, and support READ-WRITE operations.



## [1.3.0] - 2021-05-02


### Added

- Add SLL (incubating) and NULL/Loopback (incubating) codec.

- Add incubating Selection.


### Changed

- Remove @Incubating (AbstractPacket, Ethernet, Ip4, Ip6, Udp, Tcp, PacketBuffer#cast).




## [1.2.2] - 2021-03-20

### Added

- Add equals() and hashCode() to reference objects.


### Changed
- Use function mapping (method proxy) for some native method instead of direct mapping for backward compatibility.




## [1.2.1] - 2021-03-12

### Fixed

* Remove object reference if the object is GC'ed.



## [1.2.0] - 2021-02-01

### Added
- I/O multiplexor.
- Add NoSuchSelectableException.

### Changed
- Use NoSuchSelectableException on Selector#select(..) instead of NoSuchElementException.



## [1.0.7] - 2021-03-12

### Fixed

- Remove object reference if the object is GC'ed.



## [1.0.6] - 2021-01-30

### Fixed

- Fix dumper.



## [1.0.5] - 2021-01-28

### Changed

- Backward compatibility for pcap_setmintocopy(..) and update error message.



## [1.0.4] - 2021-01-24

### Changed

- Validate packet header and buffer size on pcap_dump.



## [1.0.3] - 2021-01-23

### Fixed

- Fix pcap_inject on Windows.
- Update SPDX header copyright.



## [1.0.2] - 2020-12-27

### Changed

- Only synchronize pcap_compile for before libpcap version 1.8.0.
- Backward compatibility for immediate mode on Windows (pcap_setmintocopy).
- Backward compatibility for non blocking I/O.



## [1.0.1] - 2020-12-25

### Fixed

- Fix TCP maximum data offset value.


## [1.0.0] - 2020-12-24

### Added

- Initial release.

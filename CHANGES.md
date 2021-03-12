<!--
SPDX-FileCopyrightText: 2020-2021 Pcap Project
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Changes

## Version 1.0.0

* Initial release


## Version 1.0.1

* Fix TCP maximum data offset value


## Version 1.0.2

* Only synchronize pcap_compile for before libpcap version 1.8.0
* Backward compatibility for immediate mode on Windows
* Backward compatibility for non blocking I/O 


## Version 1.0.3

* Fix pcap_inject on Windows
* Update spdx header copyright


## Version 1.0.4

* Validate packet header and buffer size on pcap_dump


## Version 1.0.5

* Backward compatibility for pcap_setmintocopy(..) and update error message


## Version 1.0.6

* Fix dumper


## Version 1.0.7 (2021-03-12)

* Remove object reference if the object is GC'ed.

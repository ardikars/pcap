<!--
SPDX-FileCopyrightText: 2020-2021 Pcap Project
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Changes

## Version 1.0.0 (2020-12-24)

* Initial release


## Version 1.0.1 (2020-12-25)

* Fix TCP maximum data offset value


## Version 1.0.2 (2020-12-27)

* Only synchronize pcap_compile for before libpcap version 1.8.0
* Backward compatibility for immediate mode on Windows (pcap_setmintocopy)
* Backward compatibility for non blocking I/O 


## Version 1.0.3 (2021-01-23)

* Fix pcap_inject on Windows
* Update SPDX header copyright


## Version 1.0.4 (2021-01-24)

* Validate packet header and buffer size on pcap_dump


## Version 1.0.5 (2021-01-28)

* Backward compatibility for pcap_setmintocopy(..) and update error message


## Version 1.0.6 (2021-01-30)

* Fix dumper


## Version 1.0.7 (2021-03-12)

* Remove object reference if the object is GC'ed.


## Version 1.1.0 (2021-02-01) - Skip this version

* I/O multiplexor


## Version 1.2.0 (2021-02-01)

* I/O multiplexor
* Add NoSuchSelectableException
* Use NoSuchSelectableException on Selector#select(..) instead of NoSuchElementException.


## Version 1.2.1 (2021-03-12)

* Remove object reference if the object is GC'ed.


## Version 1.2.2 (2021-03-20)

* Use function mapping (method proxy) for some native method instead of direct mapping for backward compatibility.

* Add equals() and hashCode() to reference objects.

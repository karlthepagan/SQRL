SQRL
====

Java SQRL (Secure QR Login) implementation. 
See https://www.grc.com/sqrl/sqrl.htm for more information on the SQRL protocol itself.

DISCLAIMER
==========

SQRL is really early days right now and is still being flushed out. This java implementation will try to stay current with the latest developments in the SQRL protocol, but everything is subject to change as the community works to create a SQRL spec.

LICENSE
=======

Apache 2.0

BUILDING
========

+ `gradle assemble` to build sqrl library
+ To create eclipse project just use `gradle cleanEclipse eclipse`, then "Import Existing Project" in eclipse.

CONTRIBUTIONS
==============

Thank you to everyone that is pitching in to help keep this java SQRL implementation up to date.

Contributors: **github.com/karlthepagan**, **github.com/brianc1969**

ATTRIBUTIONS
=============
This project utilizes the following libraries under the following licenses:
+ Apache Commons Codec (Apache 2.0)
+ github.com/wg/scrypt (Apache 2.0)
+ Apache HttpClient (Apache 2.0)
+ JUnit (BSD)
# Protocol-Attacker

![licence](https://img.shields.io/badge/License-Apachev2-brightgreen.svg)
[![Build Status](http://hydrogen.cloud.nds.rub.de/buildStatus/icon.svg?job=Protocol-Attacker)](http://hydrogen.cloud.nds.rub.de/job/Protocol-Attacker/)

Protocol-Attacker is an open-source library for the creation of Protocol-Analysis tools like TLS-Attacker or SSH-Attacker.
The tool is not intended to be used directly, but by other software projects as a library.

# Installation

In order to compile Protocol-Attacker, you need to have Java and Maven installed. On Ubuntu you can install Maven by
running:

```bash
$ sudo apt-get install maven
```

Protocol-Attacker currently needs Java JDK 11 to run. If you have the correct Java version you can install
Protocol-Attacker as follows.

```bash
$ git clone https://github.com/tls-attacker/Protocol-Attacker.git
$ cd Protocol-Attacker
$ mvn clean install
```

If you want to use this project as a dependency, you do not have to compile it yourself and can include it in your pom
.xml as follows.

```xml
<dependency>
    <groupId>de.rub.nds</groupId>
    <artifactId>protocol-attacker</artifactId>
    <version>1.1.0</version>
</dependency>
```

# Acknowledgements

The framework is developed, funded and maintained by the Ruhr University Bochum (RUB), Univerisity Paderborn (UPB), Technology Innovation Institute (TII), and the Hackmanit GmbH.

# Projects

This library is used in TLS-Attacker (https://github.com/tls-attacker/TLS-Attacker/)

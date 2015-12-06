jicmp2
======

jicmp2 provides a native ICMP interface for Java with support for both IPv4 and IPv6.

It is a rewrite and successor of [jicmp](https://github.com/OpenNMS/jicmp).

Building
--------

Requires maven (tested with 3.1.1) and cmake (tested with 2.8.12.2)

```sh
./build.sh
```

The dist/ folder should now contain both **jicmp2-api-VERSION.jar** and **libjicmp2.so**.

Packaging
---------

Requires [fpm](https://github.com/jordansissel/fpm) (tested with 1.3.3)

```sh
./build-packages.sh
```

The dist/ folder should now contain both .deb and .rpm packages.

Debian Notes
------------
On Debian 7.0, the environment can be setup with:
```sh
apt-get install openjdk-7-jdk build-essential cmake make pkg-config librrd-dev
export JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64
```


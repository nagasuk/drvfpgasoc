DrvFpgasoc (Driver to access FPGA fabric)
=========================================

Overview
--------
This is a kernel driver of Linux on FPGA SoC (e.g. Cyclone V SoC) to access FPGA fabric.

How to build
------------
Type as follows if you'd like to build for version of now running Linux.
```sh
$ make
```
Or you can use `target_kern_ver` option like below if you'd like to build for the specific version.
```sh
$ make target_kern_ver=<version of kernel which you like>
```

How to install
--------------
You can select top directory to install driver object and so on as follows.
```sh
$ make install DESTDIR=<Top directory to install>
```

Requirement
-----------
* make
* Linux kernel source


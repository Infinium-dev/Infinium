# Infinium

## About

Welcome to the repository of Infinium. Here you will find source code, instructions, wiki resources, and integration tutorials.

This is new version of infinium network, if you want to find old version of infinium network you can [here](https://github.com/converging/infinium)

Contents
* Building on Linux 64-bit
* Building on Mac OSX
* Building on Windows
* Building on other platforms

## Building on Linux 64-bit

All commands below work on Ubuntu 18.*, other distributions may need different command set.

### Building with standard options

Create directory `infdev` somewhere and go there:
```
$> mkdir infdev
$> cd infdev
```

To go futher you have to have a number of packages and utilities. You need at least gcc 5.4.

* `build-essential` package:
    ```
    $infdev> sudo apt-get install build-essential
    ```

* CMake (3.0 or newer):
    ```
    $infdev> sudo apt-get install cmake
    $infdev> cmake --version
    ```
    If version is too old, follow instructions on [the official site](https://cmake.org/download/).

* Boost (1.65 or newer):
    We use boost as a header-only library via find_boost package. So, if your system has boost installed and set up, it will be used automatically.
    
    Note - there is a bug in `boost::asio` 1.66 that affects `infiniumd`. Please use either version 1.65 or 1.67+.
    ```
    $infdev> sudo apt-get install libboost-dev
    ```
    If the latest boost installed is too old (e.g. for Ubuntu 16.*), then you need to download and unpack boost into the `infdev/boost` folder. 

    ```
    $infdev> wget -c 'https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.gz'
    $infdev> tar -xzf ./boost_1_69_0.tar.gz
    $infdev> rm ./boost_1_69_0.tar.gz
    $infdev> mv ./boost_1_69_0/ ./boost/
    ```

* OpenSSL (1.1.1 or newer):
    Install OpenSSL to `infdev/openssl` folder. (In below commands use switch `linux-x86_64-clang` instead of `linux-x86_64` if using clang.)
    ```
    $infdev> git clone https://github.com/openssl/openssl.git
    $infdev> cd openssl
    $infdev/openssl> ./Configure linux-x86_64 no-shared
    $infdev/openssl> make -j4
    $infdev/openssl> cd ..
    ```

* LMDB
    Source files are referenced via relative paths, so you do not need to separately build it:
    Please note, we use LMDB only when building 64-bit daemons. For 32-bit daemons SQLite is used instead.

    Difference to official LMDB repository is lifted 2GB database limit if built by MSVC (even of 64-bit machine).
    ```
    $infdev> git clone https://github.com/Infinium-dev/lmdb.git

    ```

Git-clone (or git-pull) Infiniumd source code in that folder:
```
$infdev> git clone https://github.com/Infinium-dev/Infinium.git
```

Create build directory inside Infinium, go there and run CMake and Make:
```
$infdev> mkdir -p Infinium/build
$infdev> cd Infinium/build
$infdev/Infinium/build> cmake ..
$infdev/Infinium/build> make -j4
```

Check built binaries by running them from `../bin` folder
```
$infdev/Infinium/build> ../bin/Infiniumd -v
```

## Building on Mac OSX

### Building with standard options (10.11 El Capitan or newer)

You need command-line tools. Either get XCode from an App Store or run 'xcode-select --install' in terminal and follow instructions. First of all, you need [Homebrew](https://brew.sh).

Then open terminal and install CMake and Boost:

* `brew install cmake`
* `brew install boost`

Create directory `infdev` somewhere and go there:
```
$~/Downloads> mkdir infdev
$~/Downloads> cd infdev
```

Git-clone (or git-pull) Infinium source code in that folder:
```
$infdev> git clone https://github.com/Infinium-dev/Infinium.git
```

Put LMDB source code in `infdev` folder (source files are referenced via relative paths, so you do not need to separately build it):
```
$~/Downloads/infdev> git clone https://github.com/Infinium-dev/lmdb.git
```

Install OpenSSL to `infdev/openssl` folder:
```
$~/Downloads/infdev> git clone https://github.com/openssl/openssl.git
$~/Downloads/infdev> cd openssl
```

If you need binaries to run on all versions of OS X starting from El Capitan, you need to build OpenSSL targeting El Capitan SDK.
```
$~/Downloads/infdev/openssl> ./Configure darwin64-x86_64-cc no-shared -mmacosx-version-min=10.11 -isysroot/Users/user/Downloads/MacOSX10.11.sdk
```
Otherwise just use
```
$~/Downloads/infdev/openssl> ./Configure darwin64-x86_64-cc no-shared
```

```
$~/Downloads/infdev/openssl> make -j4
$~/Downloads/infdev/openssl> cd ..
```

Download amalgamated [SQLite 3](https://www.sqlite.org/download.html) and unpack it into `infdev/sqlite` folder (source files are referenced via relative paths, so you do not need to separately build it).
Please, note the direct download link is periodically updated with old versions removed, so you might need to tweak instructions below
```
$~/Downloads/infdev> wget -c https://www.sqlite.org/2018/sqlite-amalgamation-3260000.zip
$~/Downloads/infdev> unzip sqlite-amalgamation-3260000.zip
$~/Downloads/infdev> rm sqlite-amalgamation-3260000.zip
$~/Downloads/infdev> mv sqlite-amalgamation-3260000 sqlite
```

Create build directory inside Infinium, go there and run CMake and Make:
```
$~/Downloads/infdev> mkdir Infinium/build
$~/Downloads/infdev> cd Infinium/build
$~/Downloads/infdev/Infinium/build> cmake ..
$~/Downloads/infdev/Infinium/build> make -j4
```

Check built binaries by running them from `../bin` folder:
```
$infdev/Infinium/build> ../bin/Infiniumd -v
```

## Building on Windows

You need Microsoft Visual Studio Community 2017. [Download](https://my.visualstudio.com/Downloads?q=visual%20studio%202017&wt.mc_id=o~msft~vscom~older-downloads) and install it selecting `C++`, `git`, `cmake integration` packages.
Run `Visual Studio x64 command prompt` from start menu.

Create directory `infdev` somewhere:
```
$C:\> mkdir infdev
$C:\> cd infdev
```

Boost (1.65 or newer):
    We use boost as a header-only library via find_boost package. So, if your system has boost installed and set up, it will be used automatically. If not, you need to download and unpack boost into infdev/boost folder.

Git-clone (or git-pull) Infinium source code in that folder:
```
$C:\infdev> git clone https://github.com/Infinium-dev/Infinium.git
```

Put LMDB in the same folder (source files are referenced via relative paths, so you do not need to separately build it):
```
$C:\infdev> git clone https://github.com/Infinium-dev/lmdb.git
```

Download amalgamated [SQLite 3](https://www.sqlite.org/download.html) and unpack it into the same folder (source files are referenced via relative paths, so you do not need to separately build it).

You need to build openssl, first install ActivePerl (select "add to PATH" option, then restart console):
```
$C:\infdev> git clone https://github.com/openssl/openssl.git
$C:\infdev> cd openssl
$C:\infdev\openssl> perl Configure VC-WIN64A no-shared no-asm
$C:\infdev\openssl> nmake
$C:\infdev\openssl> cd ..
```
If you want to build 32-bit binaries, you will also need 32-bit build of openssl in separate folder (configuring openssl changes header files, so there is no way to have both 32-bit and 64-bit versions in the same folder):
```
$C:\infdev> git clone https://github.com/openssl/openssl.git openssl32
$C:\infdev> cd openssl32
$C:\infdev\openssl> perl Configure VC-WIN32 no-shared no-asm
$C:\infdev\openssl> nmake
$C:\infdev\openssl> cd ..
```

Now launch Visual Studio, in File menu select `Open Folder`, select `C:\infdev\Infinium` folder.
Wait until CMake finishes running and `Build` appears in main menu.
Select `x64-Debug` or `x64-Release` from standard toolbar, and then `Build/Build Solution` from the main menu.

## Building with options

You can build daemons that use SQLite istead of LMDB on any platform by providing options to CMake.
You may need to clean 'build' folder, if you built with default options before, due to cmake aggressive caching.

```
$Infinium/build> cmake -DUSE_SQLITE=1 ..
$Infinium/build> time make -j8
```

## Building on 32-bit x86 platforms, iOS, Android and other ARM platforms

Infinium works on 32-bit systems if SQLite is used instead of LMDB (we've experienced lots of problems building and running with lmdb in 32-bit compatibility mode, especially on iOS).

We build official x86 32-bit version for Windows only, because there is zero demand for 32-bit version for Linux or Mac.

Building source code for iOS, Android, Raspberry PI, etc is possible (we have experimental `Infiniumd` and `walletd` running on ARM64 iPhone) but requires major skills on your part. __TBD__

## Building on Big-Endian platforms

Currently infinium does not work out of the box on any Big-Endian platform, due to some endianess-dependent code. This may be fixed in the future. If you wish to run on Big-Endian platform, please contact us.

## Building with parameters

If you want to use tools like `clang-tidy`, run `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..` instead of `cmake ..`

## Building daemons with hardware wallet support on Linux 64-bit

1. Clone `trezor-core` repository into the same folder where `infinium` resides.
2. Install all Google protobuf stuff:
```
sudo apt install protobuf-compiler libprotobuf-dev
```
3. If your version of proto buffers library is not `3.0.0`, you should run `protoc` on proto files in `trezor-core/vendor/trezor-common/protob` overwriting `infinium/src/Core/hardware/trezor/protob`.
4. Clean your `infinium/build` folder if you have built the Infinium source code before.

# rfidx

Universal RFID Tag Format Parser and Converter.

## Motivation

The motivation behind this project is the fact that there are multiple mainstream tools to work with RFID tags, and each of them has its own format for dumping the tag data. This includes:

- Proxmark3, dumps the data into raw binary format. It used to use `eml` format, but now uses `json` for loading into the FLASH for emulation. Some tools and scripts exists to convert between binary and eml, but they are limited in the tags they support.
- Flipper Zero, which uses `nfc` format for its dumps. It's a pure text unstructured format.
- Chameleon, mainly uses the raw binary format.

There isn't a unified library providing interfaces to convert between these formats, and manipulate the dumped data. This project aims to fill that gap.

### Design considerations

- Each tag type is (mostly) self-contained in its own file, with no platform specific code in the core logic. They can be taken and used directly in any other project, including embedded ones.
- Small memory footprint in its data structure and data manipulation. By default, it tries to do everything in-place with little to no memory allocation. This is particularly important for embedded systems.
- Layered approach, combining both raw data handling with higher level data structures.

## Features

- Convert between `bin`, `json`, `nfc` and `eml` formats.
- A cli tool to run the functions directly from the command line.
- A shared and static library to be used in other projects.
- Support for application level data manipulation (WIP).

## Supported tags and formats

Here is a table of the supported tags and formats:

| Tag type | Binary | JSON | NFC | EML |
|----------|--------|------|-----|-----|
| NTAG215  | ✅      | ✅    | ✅   | ❌   |

## Installation

This project is CMake based, with all production dependencies bundled in the repository. First ensure you have a compatible build system:

- CMake 3.10 or higher.
- A C compiler with C11 support. Code is only tested on Linux with GCC, so if you're building on Windows, please try to use GCC ports like MinGW or WSL if possible. MSVC in theory should work, but it hasn't been tested.

To build tests, `pkg-config` and `check` are required. Install them either via your package manager or from source.

To build the project, run the following commands:

```bash
git clone https://github.com/Firefox2100/rfidx.git
cd rfidx
git submodule update --init --recursive
cmake -S . -B build
cmake --build build --target rfidx
```

The build system will create a `build` directory, inside of which it will build the binary cli to use. To build the shared library or static library, set the target to `librfidx_shared` or `librfidx_static` respectively. There will be a script in future to wrap all the functions, including direct installation into the system.

To run the tests, build the `unit_tests` target:

```bash
cmake --build build --target unit_tests
cd build
ctest
```

The build configuration adds address sanitizer into the unit test binary, but by default it's not enabled. Specify what to enable by passing the `-DSANITIZE_ADDRESS=On` flag to cmake command. Note that address sanitizer conflicts with CLion built-in Valgrind tool, and will likely cause segmentation fault. Do not enable both at the same time.

## Usage

### CLI tool

The CLI tool is designed to convert dump formats directly. The supported arguments are:

- `-i` or `--input` to specify the input file. Can be omitted, if the operation requested does not require an input file (WIP).
- `-o` or `--output` to specify the output file. If omitted, data will be printed to stdout. In this case, binary data will be printed as hex, and text data will be printed as is.
- `-I` or `--input-type` to specify what tag the dump is for. If omitted, the tool will try to detect the type automatically (WIP).
- `-F` or `--output-format` to specify what format (NFC, JSON, etc.) to output. Must be specified if `--output` is specified. If omitted together with `--output`, the tool will **NOT** convert the data. This may be useful if you just want to validate the dump.

### Library

This project can be compiled as either a shared or a static library to be used with other projects. To use it, include the `librfidx/` headers in your code. All functions and data structures have docstrings to be referenced directly. The CLI can also be used as an example of how to use the library. If using in embedded systems, it's recommended to copy only the files you need, especially because the CLI part contains UNIX platform code to handle file IO and stdio.

## Contributing

This project is at a very early stage of development, and there are many things to be done. I would happily accept any contributions, including bug fixes, new features, documentation improvements, etc. The mostly needed help is:

- More data dump files. I do not have many different tags to work with, mostly NTAG215 and Mifare Classic 1/2k. If you have a dump of other type of tags, please **ANONYMIZE IT** by removing production data, without disrupting the dump structure, and add it to the repository. Feel free to open an issue to discuss the format of the dump, if you're not sure how to do it. This is mainly because different tools dump different tags with (usually) not unified format, and I can't guess the format of the dump without seeing it.
- More tests. Not necessarily test cases, just use it normally and report any errors would be of great help.

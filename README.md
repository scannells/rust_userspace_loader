# Linux x86_64 ELF loader in userspace

This is the result of a fun little side project where the idea is to emulate the Linux kernel's behavior when loading ELF binaries but in user-space.

This is achieved by using `mmap()` and setting up a new stack and then jumping to the entry point of either the 
ELF Interpreter that is requested by the ELF to be loaded or directly jumping to its entrypoint directly.

This essentially can be used to have 2 images, along with all their libraries run independently of each other in the same address space, as they will use their own versions of the shared objects they require.
This primitive could be used for:

* Obfuscators
* Packers
* Fuzzers using Dynamic Binary Rewriting
* Whatever you can think of

One thing I still need to figure out is how to have two seperate libc heaps co-exist peacefully at
the same time.

## Building

Some low-level inline assembly is involved so Rust nightly is required, at least at the time of writing.

In the build directory, execute

```shell
rustup default nightly
cargo build --release
rustup default stable
```


## Usage

```shell
target/release/loader /path/to/bin arg1 arg2 arg3 ... argn
```

### Example

```shell
target/release/loader /bin/ls -la /usr/lib/ld-2.32.so
```

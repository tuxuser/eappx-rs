# EAppx/EMsix unpacker/decryptor

NOTE: Work-in-progress project!

Yes, it still requires per-content keys for decryption :D

Check out <https://learn.microsoft.com/en-us/windows/win32/appxpkg/make-appx-package--makeappx-exe-#to-decrypt-a-package-with-a-key-file> for keyfile format.

## Build

Requirements:

- Rustup / Cargo

```
cargo build --release --all
```

## Usage

NOTE: Currently only commands `unpack` / `unbundle`/`info` are implemented

Check usage with

```
makeappx unpack --help
makeappx unbundle --help
makeappx info --help
```

Example to print metadata of a file

```
makeappx info -p file.eappx
```

## Credits

- WalkingCat: <https://gist.github.com/WalkingCat/1c119933f7f6ce0e00c45a4fb80f2686>
- dalion619: <https://github.com/dalion619/UnpEax>

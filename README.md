# jul11co-crypto-tools

Encrypting/decrypting files & folders

- cryptofile: Encrypt/Decrypt files
- cryptofolder: Encrypt/Decrypt files in folders
- cryptopack: Encrypt/Decrypt files and create pack

### Installation

```bash
npm install
npm link
```

#### Install FUSE (for `mount` command)

Ubuntu/Linux

```bash
sudo apt-get install libfuse-dev
```

macOS (Homebrew)

```bash
brew install pkg-config
```

macOS (MacPorts)

```bash
sudo port install osxfuse +devel
```

### Usage

```bash
cryptofile --help
```

```bash
cryptofolder --help
```

```bash
cryptopack --help
```

### License

MIT License

Copyright (c) 2018 Jul11Co

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

package.json 里替换

"@signalapp/libsignal-client": "0.91.0",

"@signalapp/libsignal-client": "link:./libsignal/node",

brew install rustup

rustup toolchain uninstall stable
rm -rf ~/.rustup/toolchains/stable-aarch64-apple-darwin
rm -rf ~/.rustup/tmp
rustup toolchain install stable
rustup default stable

cargo build
error: process didn't exit successfully: `rustc -vV` (exit status: 1)
--- stderr
error: Missing manifest in toolchain 'nightly-2026-03-23-aarch64-apple-darwin'

报错了
所以，得装 nightly-2026-03-23-aarch64-apple-darwin
```
rustup toolchain install nightly-2026-03-23-aarch64-apple-darwin

cargo build
```

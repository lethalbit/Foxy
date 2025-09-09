# Foxy - FUSE File Proxy

> [!WARNING]
> Foxy is not fit for purpose for any use, and therefore it should not be used.

Foxy is a super simple and hacky [FUSE] service that proxies and logs file operations to a target backing file. It also has the ability to [CoW] any modifications to the backing file.

## Usage

The super basic usage is as simple as:

```shell
$ foxy /path/to/proxy/file /path/to/backing/file
...
```

For more usage instructions see `foxy -h`

## License

Foxy is licensed under the [BSD-3-Clause], the full text of which can be found in the [`LICENSE`] file in the root of the [git repository].

[CoW]: https://en.wikipedia.org/wiki/Copy-on-write
[FUSE]: https://www.kernel.org/doc/html/next/filesystems/fuse.html
[BSD-3-Clause]: https://spdx.org/licenses/BSD-3-Clause.html
[`LICENSE`]: https://github.com/lethalbit/foxy/blob/main/LICENSE
[git repository]: https://github.com/lethalbit/foxy

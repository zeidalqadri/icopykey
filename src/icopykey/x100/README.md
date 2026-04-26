# x100_decrypt

`x100_decrypt` is a Python library and command line tool for normalising
MIFARE Classic card dumps exported by a variety of cloning devices.  It
supports proprietary formats like X100/CopyKey as well as raw `.mfd`
and `.bin` files, offering conversion to standard formats and
optional key recovery through external tools such as `mfoc`.

The project is built with extensibility in mind: new dump formats can
be supported by implementing a `FormatStrategy` and registering it
with the strategy registry.  Configuration can be provided via YAML to
override format offsets and control external tool integration.

> **Disclaimer:** MIFARE Classic cards are widely used for access
> control and ticketing systems.  Cloning or modifying card data
> without permission may violate local laws and system terms of
> service.  You should only use this tool on cards you own or have
> explicit authorisation to analyse.  The authors assume no liability
> for misuse.

## Features

- **Format detection and normalisation** – identify supported dump
  formats and convert them into a canonical representation.
- **Plugin architecture** – add support for new formats by creating
  custom `FormatStrategy` subclasses.
- **Concurrency** – process multiple dumps in parallel using worker
  threads.
- **Optional key recovery** – integrate with `mfoc` to recover
  missing sector keys.
- **Command line interface** – convert dumps in batch with a single
  command.

## Installation

```
pip install .
```

The project has no external dependencies beyond the standard library,
but optional features such as YAML configuration require the
`PyYAML` package.

## Usage

```
python -m x100_decrypt.cli <input>... -o <output-dir> [--format {bin,mfd,json}] \ 
    [--workers N] [--strict] [--recover-keys] --confirm-ownership
```

### Examples

Normalise all dumps in the `dumps` directory into raw `.mfd` files:

```
python -m x100_decrypt.cli dumps -o normalised --format mfd --confirm-ownership
```

Convert a single X100 export to JSON, salvaging malformed payloads:

```
python -m x100_decrypt.cli export.ckm -o json_out --format json --recover-keys --strict \ 
    --confirm-ownership
```

## Development

Contributions are welcome!  Please see the `tests/` directory for
basic test cases.  To run the test suite install `pytest` and run

```
pytest -v
```

## License

This project is released under the MIT License.  See `LICENSE` for
details.
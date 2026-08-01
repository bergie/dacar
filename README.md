# Dacar - Decentralized Access Control over Reticulum

Traditionally networked [Reticulum](https://reticulum.network) applications have handled authorization using allow lists of Reticulum identities provided either over CLI flags or a configuration file. This becomes cumbersome to manage in larger deployments or when rotating identities.

Dacar is a specification aiming to help with this, providing a way to grant and revoke permissions over the Reticulum network.

See [SPEC.md](SPEC.md) for the actual specification.

## Status

Just getting started

## Implementations

This repository contains implementations of the Dacar spec for several programming languages.

### Python

Dacar reference implementation targeting RNS.

### JavaScript

JavaScript implementation for both browsers and servers, built on `@reticulum/core`.

## Development

You can install dependencies for all implementations with:
```
make install
```

Run tests with:
```
make test
```

## License

EUPL-1.2

## Acknowledgements

Both the spec and the implementations have received significant assistance from various Large Language Models, more particularly Gemini 3.1 Pro, Claude Sonnet 5, and GLM 5.

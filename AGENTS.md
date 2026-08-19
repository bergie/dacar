This repository is for reference implementations of the Dacar spec (`SPEC.md`).

Each implementation should be written in a way that is idiomatic to that language. For example, the JavaScript implementation should be a modern ES module with JsDoc TypeScript annotations, written in a way that works on both browsers and typical server-side runtimes (like Node.js and Deno).

Just like with Reticulum, the Python implementation should be considered canonical, and other language ports should ensure interoperability with it.

We should generally avoid 3rd party dependencies. In cases where a dependency may be needed (for example for cryptography in languages that don't provide it in their standard library), we should strive to use the same dependencies as that language's primary Reticulum implementation.

This repository is for reference implementations ot the Dacar spec (`SPEC.md`).

Each implementation should we written in a way that is idiomatic to that language. For example, the JavaScript implementation should be a modern ES module with JsDoc TypeScript annotations, written in a way that works on both browsers and typical server-side runtimes (like Node.js and Deno).

Just like with Reticulum, the Pythom implementation shpuld be considered canonical, and other language ports should ensure interoperabiliyy with it.

We should generally avoid 3rd party dependencies. In cases where a dependency may be needed (for example for cryptography in languages that don't provide it in their standard library), we should strive to use the same dependencies as that language's primary Reticulum implementation.

## Work documents

Technical work is planned with work documents (in Markdown) that are managed using `rngit` tool and repository in `rns://3ea5aad068a337670f5bb8073226adb4/public/dacar`. The appropriate [pi skill extension](https://github.com/bergie/pi-rngit-work-document-skill) should be available.

When planning new work, there should always be a corresponding work document created explaining the idea. When implementing, the appropriate work document should be kept up-to-date by posting updates to it. Agent may _propose_ work documents, not _create_ them.

## Boundaries

- ✅ **Always**: write at least smoketests for any new functionality
- ✅ **Always**: ensure type safety.
- ✅ **Always**: use consistent formatting on per-language level
- ✅ **Always**: Use `git mv` instead of `mv' for renaming files
- ✅ **Always**: document any major changes in the `CHANGELOG.md`. Changes always go to the Unreleased segment
- ⚠️ **Ask first**: adding dependencies
- ⚠️ **Ask first**: modify CI config
- 🚫 **Never**: AI agents may not make commits on their own, instead notify user that there are uncommitted changes to review

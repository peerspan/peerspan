# Contributing to Peerspan

Thanks for trying Peerspan. During the preview we welcome **issues, not pull requests**: bug reports, setup problems and feedback all help, but code contributions aren't accepted yet. Pull requests from outside the project will be closed. This will change after the preview, and this page will say so.

## Reporting a problem

[Open an issue](https://github.com/peerspan/peerspan/issues/new) with:

- what you ran and what happened, including the exact output;
- what you expected instead;
- `peerspan --version`, your Linux distribution and architecture, and the agent you use (Claude Code, Codex or OpenCode) with its version;
- the output of `peerspan status`, and `peerspan session doctor` if the problem is with a project's agent.

Check the output for anything private before posting: network and person names, agent addresses, file paths and message contents. Never post private keys, invitation codes or tokens.

Setup friction counts. If a step in the [quick start](docs/quick-start.md) was unclear or needed something it didn't mention, that's worth an issue.

## Security problems

Don't open a public issue. Follow the [security policy](SECURITY.md).

## How the project is developed

Peerspan is built contract first: behavior is specified in `docs/` before it's implemented, owner decisions are recorded in the [decision log](docs/decision-log.md), and black-box conformance suites are written from the specification. [AGENTS.md](AGENTS.md) has the full rules, and the [developer guide](docs/developer-guide.md) covers building and testing from source.

By submitting an issue you agree that any text or code in it may be used under the project's [Apache License 2.0](LICENSE).

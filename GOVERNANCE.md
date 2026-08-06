# Governance

Umbra uses a maintainer-led governance model during its pre-1.0 stage.

Maintainers review and merge changes, manage releases, steward the roadmap, enforce community policies, and protect the project's trust boundaries. The path ownership model in `.github/CODEOWNERS` identifies the maintainers whose review is required for security-sensitive areas. Repository members with merge authority are the current public maintainer set.

Routine decisions are made through reviewed pull requests. Material changes to architecture, trust boundaries, licensing, contribution policy, governance, or compatibility require a public design discussion and an ADR before implementation. Security embargoes are the narrow exception and are documented publicly after coordinated disclosure when safe.

Maintainers seek rough consensus, but may make a final decision when consensus does not emerge. They should explain the tradeoff and apply it consistently. A maintainer must not approve their own protected production deployment or be the sole required reviewer for a high-risk change they authored.

New maintainers are selected based on sustained, trustworthy contributions, sound security judgment, constructive review, and willingness to perform maintenance work. Existing maintainers grant access through a recorded repository decision. Access is removed when a maintainer steps down, is inactive for an extended period, or can no longer meet the project's security and conduct expectations.

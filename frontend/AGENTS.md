# Repository Guidelines

## Project Structure & Module Organization
`app/` contains Next.js routes, layouts, and route handlers; keep new pages colocated with their data loaders. Shared UI primitives live in `components/`, while request helpers and Supabase utilities live in `lib/` and `supabase/`. Store global styles in `styles/`, static assets in `public/`, background workers in `workers/`, and end-to-end specs in `tests/e2e`.

## Build, Test, and Development Commands
Install dependencies with `pnpm install` (the `Makefile` falls back to npm if pnpm is missing). Use `pnpm dev` for the hot-reloading dev server and `pnpm build` + `pnpm start` to verify the production bundle. Run `pnpm lint` before pushing to keep ESLint happy, and `pnpm test:e2e` (optionally `-- --headed`) to execute Playwright suites. `make dev` and `make dev-open` wrap the same workflow when you prefer make targets.

## Coding Style & Naming Conventions
All code is TypeScript-first with 2-space indentation and single quotes enforced by the ESLint/Next defaults. Keep React component filenames in kebab-case (e.g., `nav-auth-button.tsx`), export components via PascalCase identifiers, and colocate hooks or helpers beside their consumers. Tailwind CSS is the primary styling tool—prefer utility classes over custom CSS unless it lives in `styles/globals.css`. Run `pnpm lint` after major refactors to catch accessibility and import ordering issues.

## Testing Guidelines
Playwright is configured through `playwright.config.ts`. Specs belong under `tests/e2e` and should follow the `*.spec.ts` suffix. Aim for deterministic flows that seed their own data via Supabase or mock endpoints; avoid depending on prior runs. When iterating on a single suite, run `pnpm test:e2e -- tests/e2e/<file>.spec.ts`. Record any new fixtures under `tests/e2e/fixtures` and keep them minimal.

## Commit & Pull Request Guidelines
Follow the Conventional Commits style already in history (`feat(frontend): …`, `fix(auth): …`). Group related changes into one commit and keep messages in the imperative mood. Pull requests should describe the motivation, list the commands/tests you ran, and link Supabase issues or design tickets. Include screenshots or short clips when UI changes affect the customer journey.

## Security & Configuration Tips
Never commit secrets; instead, copy `.env.example` to `.env.local` and fill Supabase credentials plus any optional vLLM settings. Treat `SUPABASE_SERVICE_ROLE_KEY` as production-only—use project-specific anon keys for local UI testing. Reset environment variables when switching branches to avoid leaking state into Playwright runs.

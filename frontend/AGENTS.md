# Repository Guidelines

## Structure
- `app/` holds the Next.js route tree; keep route handlers, loaders, and UI together.
- Shared UI primitives live in `components/`, shared hooks in `hooks/`, and request/Supabase helpers in `lib/` + `supabase/`.
- Global styles sit in `styles/`, Tailwind config in `tailwind.config.js`, and static assets in `public/`. Background work belongs in `workers/`.
- Tests: Playwright specs stay under `tests/e2e`, Vitest suites mirror features under `tests/unit`, and any fixtures go in `tests/e2e/fixtures`.

## Build & Test
- Install via `pnpm install`; the `Makefile` falls back to npm when pnpm is missing.
- Local dev: `pnpm dev` (or `make dev` / `make dev-open`). Production check: `pnpm build && pnpm start`.
- Quality gates: `pnpm lint`, `pnpm test:unit` (Vitest), and `pnpm test:e2e` (Playwright, append `-- --headed` when debugging). `make test` runs the Vitest + Playwright combo with the required env (`FORM_TOKEN_SECRET`, etc.).

## Style
- TypeScript-first, 2-space indentation, and keep the existing Next/Prettier double-quote formatting.
- React files use kebab-case filenames that export PascalCase components. Colocate feature-specific hooks/helpers; promote shared ones into `hooks/` or `lib/`.
- Prefer Tailwind utility classes; only touch `styles/globals.css` for custom CSS. Re-run `pnpm lint` after major refactors for accessibility/import checks.

## Version Control
- Use Conventional Commits (`feat(frontend): …`, `fix(auth): …`) in imperative mood.
- PRs must explain the motivation, list relevant commands/tests, link Supabase issues or design tickets, and include screenshots/video for UX changes.

## Security
- Copy `.env.example` to `.env.local` and never commit secrets. Use anon Supabase keys for local UI work; reserve `SUPABASE_SERVICE_ROLE_KEY` for backend-only contexts.
- Reset env vars when switching branches so Playwright and local sessions stay deterministic.
- Attestation fetch + DCAP verification must succeed before enabling encrypted chat; failures surface in the Proof-of-Confidentiality panel and keep messaging disabled.

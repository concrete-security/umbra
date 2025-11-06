# Saas Landing Page

*Automatically synced with your [v0.app](https://v0.app) deployments*

[![Deployed on Vercel](https://img.shields.io/badge/Deployed%20on-Vercel-black?style=for-the-badge&logo=vercel)](https://vercel.com/jordanfrery-3725s-projects/v0-saas-landing-page)
[![Built with v0](https://img.shields.io/badge/Built%20with-v0.app-black?style=for-the-badge)](https://v0.app/chat/projects/o951Eo6uxDK)

## Overview

This repository will stay in sync with your deployed chats on [v0.app](https://v0.app).
Any changes you make to your deployed app will be automatically pushed to this repository from [v0.app](https://v0.app).

## Deployment

Your project is live at:

**[https://vercel.com/jordanfrery-3725s-projects/v0-saas-landing-page](https://vercel.com/jordanfrery-3725s-projects/v0-saas-landing-page)**

## Build your app

Continue building your app on:

**[https://v0.app/chat/projects/o951Eo6uxDK](https://v0.app/chat/projects/o951Eo6uxDK)**

## How It Works

1. Create and modify your project using [v0.app](https://v0.app)
2. Deploy your chats from the v0 interface
3. Changes are automatically pushed to this repository
4. Vercel deploys the latest version from this repository

## How to launch it

- Go to: `cd ~/secure-llm/frontend`
- Install the dependancies: `pnpm install`
- Launch the project: `pnpm dev --hostname 0.0.0.0`
- Check if the port 3000 is used: `sudo ss -ltnp | grep 3000`
- You should see:

```
 Next.js 15.5.4
- Local:    http://localhost:3000
- Network:  http://10.0.0.182:3000
✓ Ready in xxms
 ○ Compiling / ...
 ✓ Compiled / in xxs (xx modules)
 GET / 200 in xxms
 ✓ Compiled in xxms (xx modules)
```

- For `Node/Next.jsa` dependancies are added to : `package.json` through `npm install openai`

## Configuration

Copy the example environment file and adjust optional client defaults:

- `cp .env_example .env.local`
- Only `NEXT_PUBLIC_*` variables are consumed. They are embedded in the bundle, so leave them empty if you plan to supply details from the browser UI.
- `NEXT_PUBLIC_ATTESTATION_BASE_URL` (optional) points the Proof of Confidentiality UI at the Umbra CVM attestation service so it can display the attestation origin and host metadata.
- `NEXT_PUBLIC_PHALA_TDX_VERIFIER_API` (optional, client-side) overrides the default `https://cloud-api.phala.network/api/v1/attestations/verify` endpoint used for client-side quote verification.
- All attestation and verification calls are made directly from the browser (client-side only). There is no server-side proxy or fallback.
- CORS must be enabled on both the attestation service and Phala Network verifier endpoints.
- Browser uses standard TLS certificate validation. Invalid certificates will be rejected by the browser. To connect to endpoints with invalid certificates, you must fix the certificate on the server side or manually accept it in your browser.
- Provide the vLLM base URL, model id, and bearer token from the **Provider settings** card inside the Confidential AI page. The token stays in the browser (session storage) and is never sent through a Next.js API route.
- Use `curl -H "Authorization: Bearer <your-token>" https://your-tee-host/v1/models` to inspect available model ids before populating the UI defaults.
- Update the base system prompt in `lib/system-prompt.ts` or via `NEXT_PUBLIC_DEFAULT_SYSTEM_PROMPT` if you need a different Umbra persona. The Reasoning intensity selector in the chat forwards `reasoning_effort` to the vLLM endpoint.

## Supabase setup

1. Provision a Supabase project and add `http://localhost:3000/auth/callback` (plus your deployed domain) to the list of **Redirect URLs**.
2. Copy your Supabase URL, anon key, and service role key into `.env.local`:
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY`
3. Execute the SQL in `supabase/schema.sql` inside the Supabase SQL editor to create the `waitlist_requests` table plus supporting indexes and policies.
4. Seed an administrator account (email + password) and add the `admin` role to the user’s `app_metadata` via the Supabase dashboard or SQL:
   ```sql
   update auth.users
   set raw_app_meta_data = jsonb_set(coalesce(raw_app_meta_data, '{}'), '{roles}', '["admin"]'::jsonb, true)
   where email = 'you@example.com';
   ```
5. Visit `/sign-in` locally, authenticate with the admin credentials, and you can manage the waitlist at `/admin/waitlist`.

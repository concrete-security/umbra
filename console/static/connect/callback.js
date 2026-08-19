/* /connect/oauth/callback: finish the Console PKCE login and bounce back to
 * the wizard page whose slug was stashed alongside the verifier. */
(() => {
  "use strict";

  const SESSION_KEY = "umbra_connect_session";
  const PKCE_KEY = "umbra_connect_pkce";
  const CLIENT_ID = "umbra-cli-v1";
  const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
  const statusNode = document.getElementById("status");

  async function complete() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const stored = sessionStorage.getItem(PKCE_KEY);
    sessionStorage.removeItem(PKCE_KEY);
    if (!code || !state || !stored) {
      statusNode.textContent = "Sign-in failed: missing authorization code or state. Reopen the connect link.";
      return;
    }
    let pkce;
    try {
      pkce = JSON.parse(stored);
    } catch {
      statusNode.textContent = "Sign-in failed: session expired. Reopen the connect link.";
      return;
    }
    // Require a stored state and an exact match — a missing or mismatched
    // state must fail the CSRF check, never proceed.
    if (!pkce.state || state !== pkce.state) {
      statusNode.textContent = "Sign-in failed: state mismatch.";
      return;
    }
    const response = await fetch("/api/v1/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        code_verifier: pkce.verifier,
        client_id: CLIENT_ID,
        redirect_uri: window.location.origin + "/connect/oauth/callback",
      }),
    });
    if (!response.ok) {
      let message = "Sign-in failed. Your organization may not be registered with Umbra.";
      try {
        const err = await response.json();
        message = (err.error && err.error.message) || message;
      } catch {
        /* keep default */
      }
      statusNode.textContent = message;
      return;
    }
    const tokens = await response.json();
    sessionStorage.setItem(
      SESSION_KEY,
      JSON.stringify({
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
      })
    );
    const slug = SLUG_RE.test(pkce.integration || "") ? pkce.integration : null;
    if (!slug) {
      statusNode.textContent = "Signed in. Reopen the connect link your admin shared.";
      return;
    }
    window.location.replace("/connect/" + slug);
  }

  complete();
})();

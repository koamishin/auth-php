<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;

class KoamishinAuth
{
    public function __construct(
        protected string $portalUrl,
        protected string $clientId,
        protected string $clientSecret,
        protected string $redirectUri,
    ) {
        $this->portalUrl = rtrim($portalUrl, '/');
    }

    /**
     * Generate redirect URL to Koamishin Portal with PKCE challenge.
     */
    public function getLoginUrl(?string $returnTo = null): string
    {
        $state = bin2hex(random_bytes(16));
        $codeVerifier = bin2hex(random_bytes(32));
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        Session::put('koamishin_oauth_state', $state);
        Session::put('koamishin_code_verifier', $codeVerifier);

        if ($returnTo) {
            Session::put('koamishin_return_to', $returnTo);
        }

        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid profile email roles',
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);

        return "{$this->portalUrl}/oauth/authorize?{$query}";
    }

    /**
     * Handle OAuth callback from Portal, exchange code for tokens, and return user.
     */
    public function handleCallback(string $code, string $state): KoamishinUser
    {
        $savedState = Session::get('koamishin_oauth_state');

        if (! $savedState || ! hash_equals($savedState, $state)) {
            throw new \InvalidArgumentException('Invalid OAuth state. Possible CSRF attempt.');
        }

        $codeVerifier = (string) Session::get('koamishin_code_verifier');

        $tokenResponse = Http::asForm()->post("{$this->portalUrl}/oauth/token", [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $codeVerifier,
            'code' => $code,
        ]);

        if ($tokenResponse->failed()) {
            throw new \RuntimeException('OAuth token exchange failed: '.$tokenResponse->body());
        }

        $tokenData = $tokenResponse->json();
        $accessToken = $tokenData['access_token'] ?? null;

        if (! $accessToken) {
            throw new \RuntimeException('Access token missing in OAuth response.');
        }

        $userResponse = Http::withToken($accessToken)
            ->get("{$this->portalUrl}/api/oauth/userinfo");

        if ($userResponse->failed()) {
            throw new \RuntimeException('Failed to fetch userinfo from Koamishin Portal: '.$userResponse->body());
        }

        $userData = $userResponse->json();
        $user = KoamishinUser::fromArray($userData);

        Session::put('koamishin_user', $userData);
        Session::put('koamishin_access_token', $accessToken);
        Session::forget(['koamishin_oauth_state', 'koamishin_code_verifier']);

        return $user;
    }

    /**
     * Get currently authenticated Koamishin user from local session.
     */
    public function user(): ?KoamishinUser
    {
        $data = Session::get('koamishin_user');

        if (! $data || ! is_array($data)) {
            return null;
        }

        return KoamishinUser::fromArray($data);
    }

    /**
     * Check if user is currently authenticated via Koamishin.
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Logout and destroy local session tokens.
     */
    public function logout(): void
    {
        Session::forget(['koamishin_user', 'koamishin_access_token']);
    }
}

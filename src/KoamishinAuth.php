<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use InvalidArgumentException;
use RuntimeException;

class KoamishinAuth
{
    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        protected string $portalUrl,
        protected string $clientId = '',
        protected string $clientSecret = '',
        protected string $redirectUri = '',
        protected array $scopes = ['openid', 'profile', 'email', 'roles', 'metadata:public'],
        protected string $applicationId = '',
        protected string $environment = '',
        protected string $publishableKey = '',
        protected string $secretKey = '',
    ) {
        $this->portalUrl = rtrim($portalUrl, '/');
    }

    public function isConfigured(): bool
    {
        $publishableKey = trim($this->publishableKey);

        return ($publishableKey !== '' ? $publishableKey : trim($this->clientId)) !== '';
    }

    public function resolvedEnvironment(): string
    {
        $this->validateKeyConfiguration();

        $environment = trim($this->environment);
        if ($environment !== '') {
            return $environment;
        }

        $publishableKey = trim($this->publishableKey);
        $effectiveClientId = $publishableKey !== '' ? $publishableKey : trim($this->clientId);
        $secretKey = trim($this->secretKey);
        $effectiveClientSecret = $secretKey !== '' ? $secretKey : trim($this->clientSecret);

        return self::keyEnvironment($effectiveClientId) ?? self::keyEnvironment($effectiveClientSecret) ?? '';
    }

    public function getLoginUrl(?string $returnTo = null): string
    {
        return $this->authorizationUrl($returnTo, false);
    }

    public function getRegistrationUrl(?string $returnTo = null): string
    {
        return $this->authorizationUrl($returnTo, true);
    }

    private function authorizationUrl(?string $returnTo, bool $signup): string
    {
        $this->validateApplicationContext();

        $state = bin2hex(random_bytes(16));
        $codeVerifier = bin2hex(random_bytes(32));
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
        $transactions = Session::get('koamishin_oauth_transactions', []);
        $transactions = is_array($transactions) ? $transactions : [];
        $transactions = array_filter($transactions, fn ($transaction): bool => is_array($transaction) && (int) ($transaction['created_at'] ?? 0) >= time() - 600);
        $transactions = array_slice($transactions, -9, null, true);
        $transactions[$state] = [
            'verifier' => $codeVerifier,
            'return_to' => self::safeReturnTo($returnTo),
            'created_at' => time(),
        ];
        Session::put('koamishin_oauth_transactions', $transactions);

        $parameters = [
            'client_id' => $this->effectiveClientId(),
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];
        if ($signup) {
            $parameters['screen_hint'] = 'signup';
        }

        $query = http_build_query($parameters);

        return "{$this->portalUrl}/oauth/authorize?{$query}";
    }

    public function handleCallback(string $code, string $state): KoamishinUser
    {
        $this->validateKeyConfiguration();

        $transactions = Session::get('koamishin_oauth_transactions', []);
        $transaction = is_array($transactions) ? ($transactions[$state] ?? null) : null;

        if (! preg_match('/\A[a-f0-9]{32}\z/', $state) || ! is_array($transaction) || (int) ($transaction['created_at'] ?? 0) < time() - 600 || ! is_string($transaction['verifier'] ?? null) || $code === '') {
            throw new InvalidArgumentException('Invalid or expired OAuth transaction.');
        }

        unset($transactions[$state]);
        Session::put('koamishin_oauth_transactions', $transactions);

        $response = Http::connectTimeout(3)->timeout(10)->asForm()->post("{$this->portalUrl}/oauth/token", [
            'grant_type' => 'authorization_code',
            'client_id' => $this->effectiveClientId(),
            'client_secret' => $this->effectiveClientSecret(),
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $transaction['verifier'],
            'code' => $code,
        ]);

        $tokens = $this->validatedTokens($response);
        $user = $this->userForToken($tokens['access_token']);
        if ($user === null) {
            throw new RuntimeException('Portal rejected the new access token.');
        }

        Session::regenerate(true);
        $this->storeTokens($tokens);
        Session::put('koamishin_user_id', $user->id);
        Session::put('koamishin_return_to', $transaction['return_to'] ?? null);

        return $user;
    }

    /**
     * Revalidate the stored access token and current claims against the Portal.
     */
    public function user(): ?KoamishinUser
    {
        $accessToken = $this->currentAccessToken();
        if ($accessToken === null) {
            return null;
        }

        $user = $this->userForToken($accessToken);
        $userId = Session::get('koamishin_user_id');
        if ($user === null || ! is_string($userId) || ! hash_equals($userId, $user->id)) {
            $this->clearSession();

            return null;
        }

        return $user;
    }

    /**
     * Mint a short-lived session token for the current session.
     *
     * The token can be handed to this application's own backends, which verify
     * it offline with {@see SessionTokenVerifier} instead of calling the
     * Koamishin Auth userinfo endpoint on every request.
     */
    public function sessionToken(): SessionToken
    {
        $accessToken = $this->currentAccessToken();
        if ($accessToken === null) {
            throw new RuntimeException('No active Koamishin session to mint a session token for.');
        }

        $response = Http::connectTimeout(3)->timeout(10)->withToken($accessToken)
            ->acceptJson()->post("{$this->portalUrl}/api/oauth/session-token");

        if ($response->status() === 401 || $response->status() === 403) {
            $this->clearSession();

            throw new RuntimeException('Koamishin Auth rejected the access token.');
        }
        if (! $response->successful()) {
            throw new RuntimeException('Unable to mint a session token.');
        }

        /** @var array<string, mixed> $payload */
        $payload = $response->json() ?? [];

        return SessionToken::fromArray($payload);
    }

    /**
     * Authenticate a session token offline, bound to this application.
     *
     * Returns null when the token is invalid or belongs to another application
     * or environment. Profile fields are empty on the returned user — session
     * tokens carry identity, not profile; fetch userinfo when you need more.
     */
    public function userForSessionToken(string $token): ?KoamishinUser
    {
        $this->validateApplicationContext();

        try {
            $claims = (new SessionTokenVerifier($this->portalUrl))->verify($token);
        } catch (InvalidSessionToken) {
            return null;
        }

        $applicationId = is_string($claims['application_id'] ?? null) ? $claims['application_id'] : '';
        $environment = is_string($claims['environment'] ?? null) ? $claims['environment'] : '';

        if ($applicationId === '' || $environment === '') {
            return null;
        }

        if (! hash_equals($this->applicationId, $applicationId) || ! hash_equals($this->resolvedEnvironment(), $environment)) {
            return null;
        }

        $organization = is_array($claims['o'] ?? null) ? $claims['o'] : [];

        return KoamishinUser::fromArray([
            'sub' => $claims['sub'],
            'application_id' => $applicationId,
            'environment' => $environment,
            'organization_id' => is_string($organization['id'] ?? null) ? $organization['id'] : null,
            'roles' => is_string($organization['rol'] ?? null) ? [$organization['rol']] : [],
        ]);
    }

    /**
     * Authenticate a bearer token without saving it in the session.
     */
    public function userForToken(string $accessToken): ?KoamishinUser
    {
        if ($accessToken === '') {
            return null;
        }

        $this->validateApplicationContext();

        $response = Http::connectTimeout(3)->timeout(10)->withToken($accessToken)
            ->acceptJson()->get("{$this->portalUrl}/api/oauth/userinfo");
        if ($response->status() === 401 || $response->status() === 403) {
            return null;
        }
        if (! $response->successful()) {
            throw new RuntimeException('Unable to fetch userinfo from the Portal.');
        }

        $data = $response->json();
        if (! is_array($data) || ! is_string($data['sub'] ?? null) || $data['sub'] === '' || ! is_string($data['application_id'] ?? null) || ! is_string($data['environment'] ?? null)) {
            throw new RuntimeException('Portal returned invalid userinfo.');
        }

        if (! hash_equals($this->applicationId, $data['application_id']) || ! hash_equals($this->resolvedEnvironment(), $data['environment'])) {
            return null;
        }

        return KoamishinUser::fromArray($data);
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Remove this application's Koamishin session; this does not revoke Portal tokens.
     */
    public function logout(): void
    {
        $this->clearSession();
        Session::forget(['koamishin_oauth_transactions', 'koamishin_return_to']);
        Session::regenerate(true);
    }

    public function consumeReturnTo(string $default = '/'): string
    {
        return self::safeReturnTo(Session::pull('koamishin_return_to')) ?? self::safeReturnTo($default) ?? '/';
    }

    protected function refresh(): bool
    {
        $this->validateKeyConfiguration();

        $refreshToken = $this->decryptSessionToken('koamishin_refresh_token');
        if ($refreshToken === null) {
            $this->clearSession();

            return false;
        }

        $response = Http::connectTimeout(3)->timeout(10)->asForm()->post("{$this->portalUrl}/oauth/token", [
            'grant_type' => 'refresh_token',
            'client_id' => $this->effectiveClientId(),
            'client_secret' => $this->effectiveClientSecret(),
            'refresh_token' => $refreshToken,
        ]);
        if ($response->status() >= 400 && $response->status() < 500) {
            $this->clearSession();

            return false;
        }

        $this->storeTokens($this->validatedTokens($response));

        return true;
    }

    /**
     * The stored access token for the current session, refreshing it first when
     * it has expired. Clears the session and returns null when there is none.
     */
    protected function currentAccessToken(): ?string
    {
        $accessToken = $this->decryptSessionToken('koamishin_access_token');
        $expiresAt = Session::get('koamishin_token_expires_at');
        $userId = Session::get('koamishin_user_id');
        if ($accessToken === null || ! is_numeric($expiresAt) || ! is_string($userId) || $userId === '') {
            $this->clearSession();

            return null;
        }

        if ((int) $expiresAt <= time()) {
            if (! $this->refresh()) {
                return null;
            }
            $accessToken = $this->decryptSessionToken('koamishin_access_token');
            if ($accessToken === null) {
                $this->clearSession();

                return null;
            }
        }

        return $accessToken;
    }

    /**
     * @return array{access_token: string, refresh_token: ?string, expires_in: int}
     */
    protected function validatedTokens(Response $response): array
    {
        if (! $response->successful()) {
            throw new RuntimeException('OAuth token exchange failed.');
        }
        $data = $response->json();
        $expiresIn = is_array($data) ? ($data['expires_in'] ?? null) : null;
        if (! is_array($data) || ! is_string($data['access_token'] ?? null) || $data['access_token'] === '' || ! is_numeric($expiresIn) || (int) $expiresIn <= 0 || (int) $expiresIn > PHP_INT_MAX - time()) {
            throw new RuntimeException('Portal returned an invalid token response.');
        }

        return [
            'access_token' => $data['access_token'],
            'refresh_token' => is_string($data['refresh_token'] ?? null) && $data['refresh_token'] !== '' ? $data['refresh_token'] : null,
            'expires_in' => (int) $expiresIn,
        ];
    }

    /**
     * @param  array{access_token: string, refresh_token: ?string, expires_in: int}  $tokens
     */
    protected function storeTokens(array $tokens): void
    {
        Session::put('koamishin_access_token', Crypt::encryptString($tokens['access_token']));
        Session::put('koamishin_token_expires_at', time() + $tokens['expires_in']);
        if ($tokens['refresh_token'] !== null) {
            Session::put('koamishin_refresh_token', Crypt::encryptString($tokens['refresh_token']));
        } else {
            Session::forget('koamishin_refresh_token');
        }
    }

    protected function decryptSessionToken(string $key): ?string
    {
        $value = Session::get($key);
        if (! is_string($value) || $value === '') {
            return null;
        }

        try {
            $token = Crypt::decryptString($value);

            return $token !== '' ? $token : null;
        } catch (DecryptException) {
            return null;
        }
    }

    protected function clearSession(): void
    {
        Session::forget(['koamishin_user', 'koamishin_user_id', 'koamishin_access_token', 'koamishin_refresh_token', 'koamishin_token_expires_at']);
    }

    protected function effectiveClientId(): string
    {
        $this->validateKeyConfiguration();

        $publishableKey = trim($this->publishableKey);

        return $publishableKey !== '' ? $publishableKey : trim($this->clientId);
    }

    protected function effectiveClientSecret(): string
    {
        $this->validateKeyConfiguration();

        $secretKey = trim($this->secretKey);

        return $secretKey !== '' ? $secretKey : trim($this->clientSecret);
    }

    protected function validateKeyConfiguration(): void
    {
        $publishableKey = trim($this->publishableKey);
        $clientId = trim($this->clientId);
        $secretKey = trim($this->secretKey);
        $clientSecret = trim($this->clientSecret);

        if (str_starts_with($publishableKey, 'sk_') || str_starts_with($clientId, 'sk_')) {
            throw new RuntimeException('A Koamishin secret key cannot be used as a publishable key or client ID.');
        }

        if (str_starts_with($secretKey, 'pk_') || str_starts_with($clientSecret, 'pk_')) {
            throw new RuntimeException('A Koamishin publishable key cannot be used as a secret key.');
        }

        if ($publishableKey !== '' && $clientId !== '' && $publishableKey !== $clientId) {
            throw new RuntimeException('Configure either KOAMISHIN_PUBLISHABLE_KEY or KOAMISHIN_CLIENT_ID, not conflicting values.');
        }

        $effectiveClientId = $publishableKey !== '' ? $publishableKey : $clientId;
        $effectiveClientSecret = $secretKey !== '' ? $secretKey : $clientSecret;

        $publishableEnvironment = self::keyEnvironment($effectiveClientId);
        $secretEnvironment = self::keyEnvironment($effectiveClientSecret);

        if ($publishableEnvironment !== null && $secretEnvironment !== null && $publishableEnvironment !== $secretEnvironment) {
            throw new RuntimeException('Koamishin publishable key and secret key environments do not match.');
        }

        $configuredEnvironment = trim($this->environment);
        if ($configuredEnvironment !== '') {
            if (($publishableEnvironment !== null && $publishableEnvironment !== $configuredEnvironment)
                || ($secretEnvironment !== null && $secretEnvironment !== $configuredEnvironment)) {
                throw new RuntimeException('Configured Koamishin environment does not match the key environment.');
            }
        }
    }

    protected static function keyEnvironment(string $key): ?string
    {
        if (preg_match('/\A(?:pk|sk)_(test|live)_[A-Za-z0-9_-]+\z/', trim($key), $matches) !== 1) {
            return null;
        }

        return $matches[1] === 'test' ? 'development' : 'production';
    }

    protected function validateApplicationContext(): void
    {
        $environment = $this->resolvedEnvironment();

        if (trim($this->applicationId) === '' || ! in_array($environment, ['development', 'production'], true)) {
            throw new RuntimeException('Koamishin application ID and environment must be configured.');
        }
    }

    protected static function safeReturnTo(mixed $url): ?string
    {
        if (! is_string($url) || $url === '' || ! str_starts_with($url, '/') || str_starts_with($url, '//') || preg_match('/[\x00-\x20\x7f\\\\]/', rawurldecode($url))) {
            return null;
        }

        $decoded = rawurldecode($url);
        if (str_starts_with($decoded, '//') || parse_url($url, PHP_URL_HOST) !== null) {
            return null;
        }

        return $url;
    }
}

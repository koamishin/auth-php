<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use Koamishin\Auth\KoamishinAuth;
use Koamishin\Auth\KoamishinServiceProvider;
use Koamishin\Auth\Middleware\AuthenticateWithKoamishin;
use Tests\TestCase;

require_once __DIR__.'/Support/bootstrap.php';

class KoamishinAuthTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->app->register(KoamishinServiceProvider::class);
        config([
            'koamishin.portal_url' => 'https://portal.test',
            'koamishin.client_id' => 'client-id',
            'koamishin.client_secret' => 'client-secret',
            'koamishin.redirect_uri' => 'https://client.test/callback',
            'koamishin.application_id' => '100',
            'koamishin.environment' => 'production',
            'auth.guards.koamishin' => ['driver' => 'koamishin'],
        ]);
        Session::start();
        Http::preventStrayRequests();
    }

    public function test_callback_validates_state_rotates_session_and_stores_encrypted_tokens(): void
    {
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'access-secret', 'refresh_token' => 'refresh-secret', 'expires_in' => 60]),
            'https://portal.test/api/oauth/userinfo' => Http::response(['sub' => 'user-1', 'application_id' => '100', 'environment' => 'production', 'name' => 'Example', 'email' => 'user@example.test', 'public_metadata' => ['team' => 'sales']]),
        ]);
        $auth = app(KoamishinAuth::class);
        parse_str((string) parse_url($auth->getLoginUrl('/orders?status=open'), PHP_URL_QUERY), $query);
        $oldSessionId = Session::getId();

        $user = $auth->handleCallback('code', $query['state']);

        $this->assertSame('user-1', $user->id);
        $this->assertSame(['team' => 'sales'], $user->publicMetadata);
        $this->assertNotSame($oldSessionId, Session::getId());
        $this->assertNotSame('access-secret', Session::get('koamishin_access_token'));
        $this->assertSame('access-secret', Crypt::decryptString(Session::get('koamishin_access_token')));
        $this->assertSame('/orders?status=open', $auth->consumeReturnTo());
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['code'] === 'code' && strlen($request['code_verifier']) === 64);
    }

    public function test_callback_rejects_invalid_state_before_requesting_tokens(): void
    {
        Http::fake(['https://portal.test/oauth/token' => Http::response()]);
        $auth = app(KoamishinAuth::class);
        $auth->getLoginUrl('/dashboard');

        try {
            $auth->handleCallback('code', str_repeat('a', 32));
            $this->fail('An invalid state was accepted.');
        } catch (InvalidArgumentException) {
            Http::assertNothingSent();
        }
    }

    public function test_cached_identity_without_an_access_token_is_not_authenticated(): void
    {
        Session::put('koamishin_user', ['sub' => 'user-1']);

        $this->assertFalse(app(KoamishinAuth::class)->check());
        $this->assertFalse(Session::has('koamishin_user'));
    }

    public function test_revoked_access_token_clears_the_local_identity(): void
    {
        Session::put('koamishin_user_id', 'user-1');
        Session::put('koamishin_access_token', Crypt::encryptString('revoked-token'));
        Session::put('koamishin_token_expires_at', time() + 60);
        Http::fake(['https://portal.test/api/oauth/userinfo' => Http::response([], 401)]);

        $this->assertNull(app(KoamishinAuth::class)->user());
        $this->assertFalse(Session::has('koamishin_user_id'));
        Http::assertSentCount(1);
    }

    public function test_expired_access_token_refreshes_with_the_same_client_before_revalidation(): void
    {
        Session::put('koamishin_user_id', 'user-1');
        Session::put('koamishin_access_token', Crypt::encryptString('expired-token'));
        Session::put('koamishin_refresh_token', Crypt::encryptString('old-refresh'));
        Session::put('koamishin_token_expires_at', time() - 1);
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'new-access', 'refresh_token' => 'new-refresh', 'expires_in' => 60]),
            'https://portal.test/api/oauth/userinfo' => Http::response(['sub' => 'user-1', 'application_id' => '100', 'environment' => 'production']),
        ]);

        $user = app(KoamishinAuth::class)->user();

        $this->assertSame('user-1', $user?->id);
        $this->assertSame('new-refresh', Crypt::decryptString(Session::get('koamishin_refresh_token')));
        Http::assertSent(fn ($request): bool => $request->url() === 'https://portal.test/oauth/token' && $request['grant_type'] === 'refresh_token' && $request['client_id'] === 'client-id' && $request['refresh_token'] === 'old-refresh');
    }

    public function test_guard_validates_bearer_tokens_without_using_cached_session_data(): void
    {
        Session::put('koamishin_user_id', 'cached-user');
        Session::put('koamishin_access_token', Crypt::encryptString('cached-token'));
        Session::put('koamishin_token_expires_at', time() + 60);
        Http::fake(['https://portal.test/api/oauth/userinfo' => Http::response([], 401)]);
        $request = Request::create('/private', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer invalid']);
        $this->app->instance('request', $request);
        Auth::forgetGuards();

        $this->assertNull(Auth::guard('koamishin')->user());
        Http::assertSent(fn ($sent): bool => $sent->hasHeader('Authorization', 'Bearer invalid'));
    }

    public function test_middleware_exposes_the_validated_bearer_identity_to_the_request(): void
    {
        Http::fake(['https://portal.test/api/oauth/userinfo' => Http::response([
            'sub' => 'user-1',
            'application_id' => '100',
            'environment' => 'production',
            'roles' => ['member'],
        ])]);
        $request = Request::create('/private', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer valid']);

        $response = app(AuthenticateWithKoamishin::class)->handle(
            $request,
            fn ($request) => response()->json(['id' => $request->user()?->getAuthIdentifier()]),
            'member',
        );

        $this->assertSame(['id' => 'user-1'], $response->getData(true));
        Http::assertSent(fn ($sent): bool => $sent->hasHeader('Authorization', 'Bearer valid'));
    }

    public function test_middleware_rejects_a_user_without_the_required_application_role(): void
    {
        Http::fake(['https://portal.test/api/oauth/userinfo' => Http::response([
            'sub' => 'user-1',
            'application_id' => '100',
            'environment' => 'production',
            'roles' => ['member'],
        ])]);
        $request = Request::create('/private', 'GET', server: [
            'HTTP_AUTHORIZATION' => 'Bearer valid',
            'HTTP_ACCEPT' => 'application/json',
        ]);

        $response = app(AuthenticateWithKoamishin::class)->handle($request, fn () => response('unexpected'), 'admin');

        $this->assertSame(403, $response->getStatusCode());
        Http::assertSentCount(1);
    }

    public function test_access_token_that_resolves_to_another_user_clears_the_session(): void
    {
        Session::put('koamishin_user_id', 'user-1');
        Session::put('koamishin_access_token', Crypt::encryptString('other-user-token'));
        Session::put('koamishin_token_expires_at', time() + 60);
        Http::fake(['https://portal.test/api/oauth/userinfo' => Http::response(['sub' => 'user-2', 'application_id' => '100', 'environment' => 'production'])]);

        $this->assertNull(app(KoamishinAuth::class)->user());
        $this->assertFalse(Session::has('koamishin_access_token'));
        Http::assertSentCount(1);
    }

    public function test_guard_rejects_valid_tokens_for_another_application_or_environment(): void
    {
        Http::fake(['https://portal.test/api/oauth/userinfo' => Http::sequence()
            ->push(['sub' => 'user-1', 'application_id' => '200', 'environment' => 'production'])
            ->push(['sub' => 'user-1', 'application_id' => '100', 'environment' => 'development'])]);
        foreach (['other-application-token', 'other-environment-token'] as $token) {
            $request = Request::create('/private', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
            $this->app->instance('request', $request);
            Auth::forgetGuards();

            $this->assertNull(Auth::guard('koamishin')->user());
        }
        Http::assertSentCount(2);
    }

    public function test_a_session_from_another_application_is_cleared(): void
    {
        Session::put('koamishin_user_id', 'user-1');
        Session::put('koamishin_access_token', Crypt::encryptString('other-application-token'));
        Session::put('koamishin_token_expires_at', time() + 60);
        Http::fake(['https://portal.test/api/oauth/userinfo' => Http::response([
            'sub' => 'user-1',
            'application_id' => '200',
            'environment' => 'production',
        ])]);

        $this->assertNull(app(KoamishinAuth::class)->user());
        $this->assertFalse(Session::has('koamishin_access_token'));
        Http::assertSentCount(1);
    }

    public function test_missing_application_context_fails_before_requesting_userinfo(): void
    {
        Http::fake(['https://portal.test/api/oauth/userinfo' => Http::response()]);
        config(['koamishin.application_id' => '']);

        try {
            app(KoamishinAuth::class)->userForToken('valid-token');
            $this->fail('Missing application context was accepted.');
        } catch (RuntimeException $exception) {
            $this->assertSame('Koamishin application ID and environment must be configured.', $exception->getMessage());
            Http::assertNothingSent();
        }
    }

    public function test_return_destination_rejects_external_and_protocol_relative_urls(): void
    {
        Session::put('koamishin_return_to', '//evil.test');
        $this->assertSame('/', app(KoamishinAuth::class)->consumeReturnTo('https://evil.test'));

        Session::put('koamishin_return_to', '/%2f%2fevil.test');
        $this->assertSame('/', app(KoamishinAuth::class)->consumeReturnTo());
    }
}

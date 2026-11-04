<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Koamishin\Auth\Http\Controllers\AuthenticationController;
use Koamishin\Auth\Middleware\AuthenticateKoamishin;
use Tests\TestCase;

class InstalledApplicationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (getenv('KOAMISHIN_CONSUMER_TEST') !== '1') {
            $this->markTestSkipped('This test runs in the Composer-installed consumer matrix.');
        }
    }

    public function test_cached_setup_redirects_browser_guests_and_preserves_other_guards(): void
    {
        $this->assertTrue($this->app->configurationIsCached());
        $this->assertTrue($this->app->routesAreCached());
        $loginRoute = $this->app['router']->getRoutes()->getByName('login');
        $this->assertNotNull($loginRoute);
        $this->assertSame(AuthenticationController::class.'@login', $loginRoute->getActionName());
        $this->get('/sdk-private')->assertRedirect('/koamishin/login');
        $this->getJson('/sdk-private')->assertUnauthorized();
        $this->getJson('/sdk-local-private')->assertUnauthorized();
    }

    public function test_cached_setup_completes_callback_guard_and_logout(): void
    {
        config([
            'koamishin.portal_url' => 'https://portal.test',
            'koamishin.client_id' => 'client-id',
            'koamishin.client_secret' => 'client-secret',
            'koamishin.publishable_key' => '',
            'koamishin.secret_key' => '',
            'koamishin.redirect_uri' => 'https://client.test/koamishin/callback',
            'koamishin.application_id' => '100',
            'koamishin.environment' => 'production',
        ]);
        Http::preventStrayRequests();
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'access-token', 'expires_in' => 60]),
            'https://portal.test/api/oauth/userinfo' => Http::response(['sub' => 'user-1', 'application_id' => '100', 'environment' => 'production']),
        ]);

        $login = $this->get('/koamishin/login?return_to=%2Fsdk-private')->assertRedirect();
        parse_str((string) parse_url($login->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->get('/koamishin/callback?code=code&state='.$query['state'])->assertRedirect('/sdk-private');
        $this->get('/sdk-private')->assertOk()->assertSee('user-1');
        $this->post('/koamishin/logout', ['_token' => session()->token()])->assertRedirect('/');
        Auth::forgetGuards();
        $this->get('/sdk-private')->assertRedirect('/koamishin/login');
    }

    public function test_late_guard_driver_and_alias_conflicts_fail_closed(): void
    {
        config(['auth.guards.koamishin' => ['driver' => 'session', 'provider' => 'users']]);
        $this->get('/sdk-private')->assertStatus(500);

        config(['auth.guards.koamishin' => ['driver' => 'koamishin']]);
        $this->app['router']->aliasMiddleware('koamishin.auth', 'App\\CustomMiddleware');
        $this->get('/sdk-private')->assertStatus(500);

        $this->app['router']->aliasMiddleware('koamishin.auth', AuthenticateKoamishin::class);
        Auth::viaRequest('koamishin', fn () => Auth::guard('web')->user());
        Auth::forgetGuards();
        $this->get('/sdk-private')->assertStatus(500);
    }
}

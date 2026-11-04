<?php

declare(strict_types=1);

use App\Http\Middleware\EnsureAuthenticationFeatures;
use App\Http\Middleware\EnsureOAuthApplicationAccess;
use App\Http\Middleware\EnsureSetupIsComplete;
use App\Http\Middleware\HandleInertiaRequests;
use Illuminate\Http\Request;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Koamishin\Auth\Console\LaravelReactStarterAuthRoutes;
use Koamishin\Auth\Console\SetupCommand;
use Koamishin\Auth\Http\Controllers\AuthenticationController;
use Koamishin\Auth\KoamishinAuth;
use Koamishin\Auth\KoamishinServiceProvider;
use Koamishin\Auth\Middleware\AuthenticateKoamishin;
use Koamishin\Auth\Middleware\RedirectToHostedAuthentication;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

require_once __DIR__.'/Support/bootstrap.php';

class KoamishinSetupTest extends TestCase
{
    private string $sandbox;

    protected function setUp(): void
    {
        parent::setUp();

        $this->sandbox = sys_get_temp_dir().'/koamishin-setup-test-'.bin2hex(random_bytes(12));
        mkdir($this->sandbox.'/config', 0777, true);
        mkdir($this->sandbox.'/bootstrap/cache', 0777, true);
        $this->app->useConfigPath($this->sandbox.'/config');
        $this->app->useBootstrapPath($this->sandbox.'/bootstrap');
        $this->app['router']->setRoutes(new RouteCollection);
        $this->app->forgetInstance('routes.cached');
        config(['koamishin-setup' => null]);
        $guards = config('auth.guards', []);
        unset($guards['koamishin']);
        config(['auth.guards' => $guards]);

        // The Portal harness loads this provider after Artisan has already started.
        Artisan::registerCommand($this->app->make(SetupCommand::class));
    }

    protected function tearDown(): void
    {
        if (isset($this->sandbox)) {
            $this->app['files']->deleteDirectory($this->sandbox);
        }

        parent::tearDown();
    }

    private function installStarterAuthRoutes(?string $contents = null): string
    {
        $this->app->setBasePath($this->sandbox);
        mkdir(base_path('routes'), 0777, true);
        $contents ??= (string) file_get_contents(__DIR__.'/Fixtures/laravel-react-starter-auth.php');
        file_put_contents(base_path('routes/auth.php'), $contents);
        file_put_contents(base_path('routes/web.php'), "<?php\n\nrequire __DIR__.'/auth.php';\n");

        return base_path('routes/auth.php');
    }

    public function test_interactive_setup_prompts_before_replacing_supported_starter_auth_routes(): void
    {
        $path = $this->installStarterAuthRoutes();
        $originalContents = file_get_contents($path);

        $this->artisan('koamishin:setup')
            ->expectsConfirmation('Replace the unmodified Laravel React Starter Kit authentication routes with Koamishin routes?', 'yes')
            ->assertExitCode(0);

        $replacement = (string) file_get_contents($path);
        $this->assertNotSame($originalContents, $replacement);
        $this->assertTrue(LaravelReactStarterAuthRoutes::isReplacement($replacement));
        $this->assertStringContainsString(AuthenticationController::class, $replacement);
        $this->assertStringNotContainsString('RegisteredUserController', $replacement);
    }

    public function test_declining_the_starter_route_prompt_preserves_the_local_routes(): void
    {
        $path = $this->installStarterAuthRoutes();
        $originalContents = file_get_contents($path);

        $this->artisan('koamishin:setup')
            ->expectsConfirmation('Replace the unmodified Laravel React Starter Kit authentication routes with Koamishin routes?', 'no')
            ->assertExitCode(0);

        $this->assertSame($originalContents, file_get_contents($path));
    }

    public function test_non_interactive_setup_does_not_replace_starter_routes_without_the_explicit_option(): void
    {
        $path = $this->installStarterAuthRoutes();
        $originalContents = file_get_contents($path);

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame($originalContents, file_get_contents($path));
    }

    public function test_explicit_route_replacement_is_idempotent(): void
    {
        $path = $this->installStarterAuthRoutes();

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--replace-starter-auth-routes' => true, '--no-interaction' => true]));
        $replacement = file_get_contents($path);
        $this->assertTrue(LaravelReactStarterAuthRoutes::isReplacement((string) $replacement));

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--replace-starter-auth-routes' => true, '--no-interaction' => true]));
        $this->assertSame($replacement, file_get_contents($path));
    }

    public function test_replaced_starter_routes_dispatch_to_the_sdk_controller(): void
    {
        $path = $this->installStarterAuthRoutes();

        $this->assertSame(0, Artisan::call('koamishin:setup', [
            '--migrate-hosted-routes' => true,
            '--replace-starter-auth-routes' => true,
            '--no-interaction' => true,
        ]));

        config(['koamishin-setup' => require config_path('koamishin-setup.php')]);
        $this->app->register(KoamishinServiceProvider::class, true);
        Route::middleware('web')->group(function () use ($path): void {
            require $path;
        });
        Route::getRoutes()->refreshNameLookups();

        foreach (['login', 'register', 'logout'] as $action) {
            $route = Route::getRoutes()->getByName($action);
            $this->assertNotNull($route);
            $this->assertSame(AuthenticationController::class.'@'.$action, $route->getActionName());
        }

        $this->assertNull(Route::getRoutes()->getByName('password.email'));
        $this->assertNull(Route::getRoutes()->getByName('password.store'));
        $this->assertNull(Route::getRoutes()->getByName('verification.notice'));
        $this->assertNull(Route::getRoutes()->getByName('password.confirm'));
    }

    public function test_route_replacement_preserves_crlf_line_endings(): void
    {
        $stockContents = (string) file_get_contents(__DIR__.'/Fixtures/laravel-react-starter-auth.php');
        $normalizedStockContents = str_replace(["\r\n", "\r"], "\n", $stockContents);
        $path = $this->installStarterAuthRoutes(str_replace("\n", "\r\n", $normalizedStockContents));

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--replace-starter-auth-routes' => true, '--no-interaction' => true]));

        $replacement = (string) file_get_contents($path);
        $this->assertTrue(LaravelReactStarterAuthRoutes::isReplacement($replacement));
        $this->assertDoesNotMatchRegularExpression('/(?<!\r)\n/', $replacement);
    }

    public function test_explicit_route_replacement_refuses_custom_or_unloaded_routes_without_changing_files(): void
    {
        $customContents = (string) file_get_contents(__DIR__.'/Fixtures/laravel-react-starter-auth.php')."\n// application customization\n";
        $path = $this->installStarterAuthRoutes($customContents);

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--replace-starter-auth-routes' => true, '--no-interaction' => true]));
        $this->assertSame($customContents, file_get_contents($path));
        $this->assertFileDoesNotExist(config_path('koamishin-setup.php'));

        file_put_contents($path, file_get_contents(__DIR__.'/Fixtures/laravel-react-starter-auth.php'));
        file_put_contents(base_path('routes/web.php'), "<?php\n\n// Auth routes are not loaded here.\n");

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--replace-starter-auth-routes' => true, '--no-interaction' => true]));
        $this->assertTrue(LaravelReactStarterAuthRoutes::isStock((string) file_get_contents($path)));
        $this->assertFileDoesNotExist(config_path('koamishin-setup.php'));
    }

    public function test_setup_creates_a_repeatable_marker_without_changing_existing_config(): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        $existingConfig = "<?php\n\nreturn ['custom' => 'preserved'];\n";
        file_put_contents(config_path('koamishin.php'), $existingConfig);
        Route::get('/koamishin/login-help', fn () => 'help')->name('koamishin.login-help');

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $marker = config_path('koamishin-setup.php');
        $this->assertFileExists($marker);
        $this->assertSame(['enabled' => true, 'migrate_hosted_routes' => false], require $marker);
        $firstContents = file_get_contents($marker);

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame($firstContents, file_get_contents($marker));
        $this->assertSame($existingConfig, file_get_contents(config_path('koamishin.php')));
    }

    public function test_setup_refuses_a_non_matching_marker_without_overwriting_it(): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        $marker = config_path('koamishin-setup.php');
        $contents = "<?php\n\nreturn ['enabled' => false, 'custom' => 'keep'];\n";
        file_put_contents($marker, $contents);

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame($contents, file_get_contents($marker));
    }

    public function test_setup_accepts_crlf_in_an_unmodified_marker_without_rewriting_it(): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $path = config_path('koamishin-setup.php');
        $contents = str_replace("\n", "\r\n", file_get_contents($path));
        file_put_contents($path, $contents);

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame($contents, file_get_contents($path));
    }

    public function test_explicit_migration_never_overwrites_an_existing_marker(): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $path = config_path('koamishin-setup.php');

        $originalContents = file_get_contents($path);
        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--migrate-hosted-routes' => true, '--no-interaction' => true]));
        $this->assertSame($originalContents, file_get_contents($path));

        unlink($path);
        $this->assertSame(0, Artisan::call('koamishin:setup', ['--migrate-hosted-routes' => true, '--no-interaction' => true]));
        $this->assertSame(['enabled' => true, 'migrate_hosted_routes' => true], require $path);
        $contents = file_get_contents($path);
        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame($contents, file_get_contents($path));
        $crlfContents = str_replace("\n", "\r\n", $contents);
        file_put_contents($path, $crlfContents);
        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame($crlfContents, file_get_contents($path));
    }

    public function test_setup_refuses_a_conflicting_guard_without_creating_a_marker(): void
    {
        config(['auth.guards.koamishin' => ['driver' => 'session', 'provider' => 'users']]);
        $this->app->register(KoamishinServiceProvider::class);

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertFileDoesNotExist(config_path('koamishin-setup.php'));
        $this->assertSame(['driver' => 'session', 'provider' => 'users'], config('auth.guards.koamishin'));
    }

    public function test_setup_refuses_a_conflicting_middleware_alias_without_creating_a_marker(): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        $this->app['router']->aliasMiddleware('koamishin.auth', 'App\\CustomMiddleware');

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertFileDoesNotExist(config_path('koamishin-setup.php'));
        $this->assertSame('App\\CustomMiddleware', $this->app['router']->getMiddleware()['koamishin.auth']);
    }

    #[DataProvider('legacyAuthorizationClients')]
    public function test_setup_preserves_active_legacy_hosted_routes_without_explicit_migration(string $clientId, string $publishableKey): void
    {
        config([
            'koamishin.client_id' => $clientId,
            'koamishin.publishable_key' => $publishableKey,
            'koamishin.hosted_auth_routes' => true,
        ]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->app->forgetInstance(KoamishinAuth::class);
        $route = Route::get('/login', fn () => 'local')->name('login');
        $guard = config('auth.guards');
        $middleware = $this->app['router']->getMiddlewareGroups()['web'];

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame(['enabled' => true, 'migrate_hosted_routes' => false], require config_path('koamishin-setup.php'));
        $this->assertSame($guard, config('auth.guards'));
        $this->assertSame($middleware, $this->app['router']->getMiddlewareGroups()['web']);
        $this->assertContains($route, Route::getRoutes()->getRoutes());
    }

    public static function legacyAuthorizationClients(): array
    {
        return [
            'legacy client id' => ['client-id', ''],
            'publishable key' => ['', 'pk_test_example'],
        ];
    }

    public function test_explicit_legacy_migration_is_repeatable_without_the_flag(): void
    {
        config([
            'koamishin.client_id' => 'client-id',
            'koamishin.publishable_key' => '',
            'koamishin.hosted_auth_routes' => true,
        ]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->app->forgetInstance(KoamishinAuth::class);
        $route = Route::get('/login', fn () => 'local')->name('login');
        $guard = config('auth.guards');

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--migrate-hosted-routes' => true, '--no-interaction' => true]));
        $marker = file_get_contents(config_path('koamishin-setup.php'));
        $this->assertSame(['enabled' => true, 'migrate_hosted_routes' => true], require config_path('koamishin-setup.php'));
        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame($marker, file_get_contents(config_path('koamishin-setup.php')));
        $this->assertSame($guard, config('auth.guards'));
        $this->assertContains($route, Route::getRoutes()->getRoutes());
    }

    #[DataProvider('inactiveLegacyHostedRoutes')]
    public function test_setup_needs_no_migration_flag_when_legacy_interception_is_inactive(string $clientId, string $publishableKey, bool $enabled): void
    {
        config([
            'koamishin.client_id' => $clientId,
            'koamishin.publishable_key' => $publishableKey,
            'koamishin.hosted_auth_routes' => $enabled,
        ]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->app->forgetInstance(KoamishinAuth::class);

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertFileExists(config_path('koamishin-setup.php'));
    }

    public static function inactiveLegacyHostedRoutes(): array
    {
        return [
            'no authorization client' => ['', '', true],
            'blank authorization client' => ['  ', '  ', true],
            'hosted routes disabled' => ['client-id', '', false],
        ];
    }

    public function test_setup_preserves_legacy_routing_even_if_console_kernel_reset_the_web_group(): void
    {
        config([
            'koamishin.client_id' => 'client-id',
            'koamishin.hosted_auth_routes' => true,
        ]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->app->forgetInstance(KoamishinAuth::class);
        $this->app['router']->removeMiddlewareFromGroup('web', RedirectToHostedAuthentication::class);

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame(['enabled' => true, 'migrate_hosted_routes' => false], require config_path('koamishin-setup.php'));
    }

    #[DataProvider('conflictingRoutes')]
    public function test_setup_refuses_conflicting_routes_without_creating_a_marker(string $method, string $uri, ?string $name): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        $route = Route::match([$method], $uri, fn () => 'existing');
        if ($name !== null) {
            $route->name($name);
        }
        Route::getRoutes()->refreshNameLookups();

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertFileDoesNotExist(config_path('koamishin-setup.php'));
        $this->assertContains($route, Route::getRoutes()->getRoutes());
    }

    public function test_first_setup_refuses_an_app_route_that_looks_like_the_sdk_callback(): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        Route::middleware('web')->get('/koamishin/callback', [AuthenticationController::class, 'callback'])->name('koamishin.callback');

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertFileDoesNotExist(config_path('koamishin-setup.php'));
    }

    public function test_setup_allows_a_fallback_route_but_rejects_a_reserved_fallback_name(): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        $fallback = Route::fallback(fn () => 'not found');

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));

        $fallback->name('koamishin.callback');
        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
    }

    public function test_setup_refuses_a_matching_parameterized_route_on_another_domain(): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        Route::domain('other.example')->get('/koamishin/{action}', fn () => 'existing');

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertFileDoesNotExist(config_path('koamishin-setup.php'));
    }

    public function test_rerun_accepts_unchanged_enabled_sdk_routes(): void
    {
        $path = config_path('koamishin-setup.php');
        file_put_contents($path, "<?php\n\nreturn [\n    'enabled' => true,\n    'migrate_hosted_routes' => true,\n];\n");
        config(['koamishin-setup' => require $path]);
        $this->app->register(KoamishinServiceProvider::class);

        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
    }

    #[DataProvider('alteredCallbackRoutes')]
    public function test_rerun_refuses_sdk_looking_routes_with_an_altered_contract(string $alteration): void
    {
        $path = config_path('koamishin-setup.php');
        $contents = "<?php\n\nreturn [\n    'enabled' => true,\n    'migrate_hosted_routes' => true,\n];\n";
        file_put_contents($path, $contents);
        config(['koamishin-setup' => require $path]);
        $this->app->register(KoamishinServiceProvider::class);
        $route = $alteration === 'methods'
            ? Route::match(['GET', 'POST'], '/koamishin/callback', [AuthenticationController::class, 'callback'])
            : Route::get('/koamishin/callback', [AuthenticationController::class, 'callback']);
        $route->name('koamishin.callback')->middleware('web');
        if ($alteration === 'domain') {
            $route->domain('other.example');
        }
        if ($alteration === 'middleware') {
            $route->middleware('auth:web');
        }

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertSame($contents, file_get_contents($path));
    }

    public static function alteredCallbackRoutes(): array
    {
        return [['methods'], ['domain'], ['middleware']];
    }

    public static function conflictingRoutes(): array
    {
        return [
            'login URI' => ['GET', '/koamishin/login', null],
            'login HEAD URI' => ['HEAD', '/koamishin/login', null],
            'register URI' => ['GET', '/koamishin/register', null],
            'callback URI' => ['GET', '/koamishin/callback', null],
            'logout URI' => ['POST', '/koamishin/logout', null],
            'parameterized URI' => ['GET', '/koamishin/{action}', null],
            'login name' => ['GET', '/existing-login', 'koamishin.login'],
            'register name' => ['GET', '/existing-register', 'koamishin.register'],
            'callback name' => ['GET', '/existing-callback', 'koamishin.callback'],
            'logout name' => ['POST', '/existing-logout', 'koamishin.logout'],
        ];
    }

    #[DataProvider('cachePaths')]
    public function test_setup_refuses_cached_configuration_or_routes(string $cache): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        $path = $cache === 'config' ? $this->app->getCachedConfigPath() : $this->app->getCachedRoutesPath();
        $sandbox = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $this->sandbox);
        $this->assertStringStartsWith($sandbox.DIRECTORY_SEPARATOR, str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path));
        file_put_contents($path, "<?php return [];\n");
        $this->app->forgetInstance('routes.cached');
        $this->app->forgetInstance('config_loaded_from_cache');

        $this->assertNotSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        $this->assertFileDoesNotExist(config_path('koamishin-setup.php'));
        $this->assertSame("<?php return [];\n", file_get_contents($path));
    }

    public static function cachePaths(): array
    {
        return ['configuration cache' => ['config'], 'route cache' => ['routes']];
    }

    public function test_without_a_marker_the_provider_does_not_enable_setup_routes_or_a_guard(): void
    {
        $this->app->register(KoamishinServiceProvider::class);

        $this->assertNull(config('auth.guards.koamishin'));
        foreach (['login', 'register', 'callback', 'logout'] as $action) {
            $this->assertNull(Route::getRoutes()->getByName('koamishin.'.$action));
        }
    }

    public function test_enabled_marker_registers_the_guard_and_dedicated_web_routes(): void
    {
        file_put_contents(config_path('koamishin-setup.php'), "<?php return ['enabled' => true];\n");
        config(['koamishin-setup' => require config_path('koamishin-setup.php')]);
        $this->app->register(KoamishinServiceProvider::class);
        Route::getRoutes()->refreshNameLookups();

        $this->assertSame('koamishin', config('auth.guards.koamishin.driver'));
        $this->assertSame(AuthenticateKoamishin::class, $this->app['router']->getMiddleware()['koamishin.auth']);

        foreach (['login' => 'GET', 'register' => 'GET', 'callback' => 'GET', 'logout' => 'POST'] as $action => $method) {
            $route = Route::getRoutes()->getByName('koamishin.'.$action);
            $this->assertNotNull($route, "Missing koamishin.{$action} route.");
            $this->assertSame('koamishin/'.$action, $route->uri());
            $this->assertContains($method, $route->methods());
            $this->assertSame($method === 'GET' ? ['GET', 'HEAD'] : ['POST'], $route->methods());
            $this->assertSame(AuthenticationController::class.'@'.$action, $route->getActionName());
            $this->assertContains('web', $route->gatherMiddleware());
        }
    }

    public function test_enabled_marker_preserves_an_existing_compatible_guard(): void
    {
        config([
            'koamishin-setup' => ['enabled' => true],
            'auth.guards.koamishin' => ['driver' => 'koamishin', 'custom' => 'preserved'],
        ]);

        $this->app->register(KoamishinServiceProvider::class);

        $this->assertSame(['driver' => 'koamishin', 'custom' => 'preserved'], config('auth.guards.koamishin'));
    }

    public function test_enabled_setup_rejects_an_incompatible_guard_at_boot(): void
    {
        config([
            'koamishin-setup' => ['enabled' => true],
            'auth.guards.koamishin' => ['driver' => 'session', 'provider' => 'users'],
        ]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('koamishin guard must use the koamishin driver');
        $this->app->register(KoamishinServiceProvider::class);
    }

    public function test_enabled_setup_rejects_a_conflicting_alias_at_boot(): void
    {
        config(['koamishin-setup' => ['enabled' => true]]);
        $this->app['router']->aliasMiddleware('koamishin.auth', 'App\\CustomMiddleware');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('koamishin.auth middleware alias is already in use');
        $this->app->register(KoamishinServiceProvider::class);
    }

    public function test_credentialless_setup_keeps_legacy_interception_when_credentials_appear(): void
    {
        $this->app->register(KoamishinServiceProvider::class);
        $this->assertSame(0, Artisan::call('koamishin:setup', ['--no-interaction' => true]));
        config([
            'koamishin-setup' => require config_path('koamishin-setup.php'),
            'koamishin.portal_url' => 'https://portal.test',
            'koamishin.client_id' => 'client-id',
            'koamishin.redirect_uri' => 'https://client.test/koamishin/callback',
            'koamishin.application_id' => '100',
            'koamishin.environment' => 'production',
            'koamishin.hosted_auth_routes' => true,
        ]);
        $this->app->forgetInstance(KoamishinAuth::class);
        $this->app->register(KoamishinServiceProvider::class, true);
        $this->withoutMiddleware([
            HandleInertiaRequests::class,
            EnsureSetupIsComplete::class,
            EnsureAuthenticationFeatures::class,
            EnsureOAuthApplicationAccess::class,
        ]);
        Route::middleware('web')->get('/login', fn () => response('local login'));

        $response = $this->get('/login')->assertRedirect();
        $this->assertStringStartsWith('https://portal.test/oauth/authorize?', $response->headers->get('Location'));
    }

    #[DataProvider('lateSetupConflicts')]
    public function test_http_requests_fail_closed_when_setup_configuration_changes_after_boot(string $conflict): void
    {
        config(['koamishin-setup' => ['enabled' => true, 'migrate_hosted_routes' => true]]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->withoutMiddleware([
            HandleInertiaRequests::class,
            EnsureSetupIsComplete::class,
            EnsureAuthenticationFeatures::class,
            EnsureOAuthApplicationAccess::class,
        ]);
        $controllerCalled = false;
        Route::middleware(['web', 'auth:koamishin'])->get('/private', function () use (&$controllerCalled) {
            $controllerCalled = true;

            return response('private content');
        });
        if ($conflict === 'guard') {
            config(['auth.guards.koamishin' => ['driver' => 'session', 'provider' => 'users']]);
        } elseif ($conflict === 'driver') {
            Auth::viaRequest('koamishin', fn () => Auth::guard('web')->user());
            Auth::forgetGuards();
        } else {
            $this->app['router']->aliasMiddleware('koamishin.auth', 'App\\CustomMiddleware');
        }

        $this->get('/private')->assertStatus(500);
        $this->assertFalse($controllerCalled);
    }

    public static function lateSetupConflicts(): array
    {
        return [['guard'], ['driver'], ['alias']];
    }

    public function test_setup_mode_does_not_intercept_the_host_app_login_or_registration(): void
    {
        config([
            'koamishin-setup' => ['enabled' => true, 'migrate_hosted_routes' => true],
            'koamishin.portal_url' => 'https://portal.test',
            'koamishin.client_id' => 'client-id',
            'koamishin.redirect_uri' => 'https://client.test/koamishin/callback',
            'koamishin.application_id' => '100',
            'koamishin.environment' => 'production',
        ]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->withoutMiddleware([
            HandleInertiaRequests::class,
            EnsureSetupIsComplete::class,
            EnsureAuthenticationFeatures::class,
            EnsureOAuthApplicationAccess::class,
        ]);
        Route::middleware('web')->get('/login', fn () => response('local login'));
        Route::middleware('web')->get('/register', fn () => response('local registration'));
        Route::middleware('web')->post('/register', fn () => response('local registration submitted'));

        $this->get('/login')->assertOk()->assertSee('local login');
        $this->get('/register')->assertOk()->assertSee('local registration');
        $this->post('/register')->assertOk()->assertSee('local registration submitted');
    }

    public function test_dedicated_routes_complete_login_authentication_and_logout(): void
    {
        config([
            'koamishin-setup' => ['enabled' => true],
            'koamishin.portal_url' => 'https://portal.test',
            'koamishin.client_id' => 'client-id',
            'koamishin.client_secret' => 'client-secret',
            'koamishin.redirect_uri' => 'https://client.test/koamishin/callback',
            'koamishin.application_id' => '100',
            'koamishin.environment' => 'production',
        ]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->withoutMiddleware([
            HandleInertiaRequests::class,
            EnsureSetupIsComplete::class,
            EnsureAuthenticationFeatures::class,
            EnsureOAuthApplicationAccess::class,
        ]);
        Http::preventStrayRequests();
        Http::fake([
            'https://portal.test/oauth/token' => Http::response(['access_token' => 'access-token', 'expires_in' => 60]),
            'https://portal.test/api/oauth/userinfo' => Http::response(['sub' => 'user-1', 'application_id' => '100', 'environment' => 'production']),
        ]);
        Route::middleware('web')->get('/login', fn () => response('local login'))->name('login');
        Route::middleware(['web', 'auth:koamishin'])->get('/private', fn (Request $request) => $request->user()->getAuthIdentifier());
        Route::getRoutes()->refreshNameLookups();

        $login = $this->get('/koamishin/login?return_to=%2Fprivate')->assertRedirect();
        parse_str((string) parse_url($login->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->get('/koamishin/callback?code=code&state='.$query['state'])->assertRedirect('/private');
        $this->get('/private')->assertOk()->assertSee('user-1');
        $this->post('/koamishin/logout')->assertRedirect('/');
        Auth::forgetGuards();
        $this->get('/private')->assertRedirect('/login');
    }

    public function test_dedicated_middleware_redirects_browser_guests_without_a_host_login_route_and_returns_json_401(): void
    {
        config(['koamishin-setup' => ['enabled' => true, 'migrate_hosted_routes' => true]]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->withoutMiddleware([
            HandleInertiaRequests::class,
            EnsureSetupIsComplete::class,
            EnsureAuthenticationFeatures::class,
            EnsureOAuthApplicationAccess::class,
        ]);
        Route::middleware(['web', 'koamishin.auth'])->get('/private', fn () => response('private'));
        Route::getRoutes()->refreshNameLookups();

        $this->assertNull(Route::getRoutes()->getByName('login'));
        $this->get('/private')->assertRedirect(route('koamishin.login'));
        $this->getJson('/private')->assertUnauthorized();
    }

    public function test_dedicated_middleware_does_not_change_the_host_guard_or_login(): void
    {
        config(['koamishin-setup' => ['enabled' => true]]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->withoutMiddleware([
            HandleInertiaRequests::class,
            EnsureSetupIsComplete::class,
            EnsureAuthenticationFeatures::class,
            EnsureOAuthApplicationAccess::class,
        ]);
        Route::middleware('web')->get('/login', fn () => response('local login'))->name('login');
        Route::middleware(['web', 'auth:web'])->get('/local-private', fn () => response('local private'));
        Route::middleware(['web', 'koamishin.auth'])->get('/koamishin-private', fn () => response('private'));
        Route::getRoutes()->refreshNameLookups();

        $this->get('/login')->assertOk()->assertSee('local login');
        $this->get('/local-private')->assertRedirect('/login');
        $this->get('/koamishin-private')->assertRedirect(route('koamishin.login'));
    }

    public function test_callback_rejects_an_invalid_state_without_contacting_the_portal(): void
    {
        config(['koamishin-setup' => ['enabled' => true]]);
        $this->app->register(KoamishinServiceProvider::class);
        $this->withoutMiddleware([
            HandleInertiaRequests::class,
            EnsureSetupIsComplete::class,
            EnsureAuthenticationFeatures::class,
            EnsureOAuthApplicationAccess::class,
        ]);
        Http::preventStrayRequests();
        Http::fake(['https://portal.test/*' => Http::response()]);

        $this->get('/koamishin/callback?code=code&state='.str_repeat('a', 32))->assertForbidden();
        Http::assertNothingSent();
    }
}

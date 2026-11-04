<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Koamishin\Auth\Console\SetupCommand;
use Koamishin\Auth\Http\Controllers\AuthenticationController;
use Koamishin\Auth\Middleware\AuthenticateKoamishin;
use Koamishin\Auth\Middleware\EnsureSetupIntegrity;
use Koamishin\Auth\Middleware\RedirectToHostedAuthentication;
use RuntimeException;

class KoamishinServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/koamishin.php', 'koamishin');

        if ($this->app['config']->get('koamishin-setup.enabled') === true) {
            $guard = $this->app['config']->get('auth.guards.koamishin');
            if ($guard === null) {
                $this->app['config']->set('auth.guards.koamishin', ['driver' => 'koamishin']);
            } elseif (! is_array($guard) || ($guard['driver'] ?? null) !== 'koamishin') {
                throw new RuntimeException('The koamishin guard must use the koamishin driver while setup is enabled.');
            }

            $installIntegrityMiddleware = function ($kernel): void {
                if (! method_exists($kernel, 'prependMiddleware')) {
                    throw new RuntimeException('The HTTP kernel cannot enforce Koamishin setup integrity.');
                }

                $kernel->prependMiddleware(EnsureSetupIntegrity::class);
            };
            if ($this->app->resolved(Kernel::class)) {
                $installIntegrityMiddleware($this->app->make(Kernel::class));
            } else {
                $this->app->afterResolving(Kernel::class, $installIntegrityMiddleware);
            }
        }

        if ($this->app->runningInConsole()) {
            $this->commands([SetupCommand::class]);
        }

        $this->app->singleton(KoamishinAuth::class, function ($app) {
            $config = $app['config']->get('koamishin');

            return new KoamishinAuth(
                portalUrl: (string) ($config['portal_url'] ?? ''),
                clientId: (string) ($config['client_id'] ?? ''),
                clientSecret: (string) ($config['client_secret'] ?? ''),
                redirectUri: (string) ($config['redirect_uri'] ?? ''),
                scopes: is_array($config['scopes'] ?? null) ? $config['scopes'] : ['openid', 'profile', 'email', 'roles', 'metadata:public'],
                applicationId: (string) ($config['application_id'] ?? ''),
                environment: (string) ($config['environment'] ?? ''),
                publishableKey: (string) ($config['publishable_key'] ?? ''),
                secretKey: (string) ($config['secret_key'] ?? ''),
            );
        });

        $this->app->singleton(KoamishinManagementClient::class, function ($app) {
            $config = $app['config']->get('koamishin');

            return new KoamishinManagementClient(
                portalUrl: (string) ($config['portal_url'] ?? ''),
                clientId: (string) ($config['management_client_id'] ?? ''),
                clientSecret: (string) ($config['management_client_secret'] ?? ''),
                secretKey: (string) ($config['secret_key'] ?? ''),
            );
        });
    }

    public function boot(): void
    {
        if ($this->app['config']->get('koamishin-setup.enabled') === true) {
            $alias = $this->app['router']->getMiddleware()['koamishin.auth'] ?? null;
            if ($alias !== null && $alias !== AuthenticateKoamishin::class) {
                throw new RuntimeException('The koamishin.auth middleware alias is already in use.');
            }
            if ($alias === null) {
                $this->app['router']->aliasMiddleware('koamishin.auth', AuthenticateKoamishin::class);
            }

            if (! $this->app->routesAreCached()) {
                Route::middleware('web')->prefix('koamishin')->name('koamishin.')->group(function (): void {
                    Route::get('/login', [AuthenticationController::class, 'login'])->name('login');
                    Route::get('/register', [AuthenticationController::class, 'register'])->name('register');
                    Route::get('/callback', [AuthenticationController::class, 'callback'])->name('callback');
                    Route::post('/logout', [AuthenticationController::class, 'logout'])->name('logout');
                });
            }
        }

        if ($this->app['config']->get('koamishin-setup.enabled') !== true
            || $this->app['config']->get('koamishin-setup.migrate_hosted_routes') !== true) {
            $this->app['router']->pushMiddlewareToGroup('web', RedirectToHostedAuthentication::class);
            $this->app->afterResolving(Kernel::class, function (): void {
                $this->app['router']->pushMiddlewareToGroup('web', RedirectToHostedAuthentication::class);
            });

            if (! $this->app->routesAreCached()) {
                Route::middleware('web')->group(function (): void {
                    Route::get('/login', [RedirectToHostedAuthentication::class, 'fallback'])->name('login');
                    Route::get('/register', [RedirectToHostedAuthentication::class, 'fallback'])->name('register');
                });
            }
        }

        Auth::extend('koamishin', function ($app): KoamishinRequestGuard {
            $guard = new KoamishinRequestGuard(function (Request $request) use ($app): ?KoamishinUser {
                $auth = $app->make(KoamishinAuth::class);
                if ($request->headers->has('Authorization')) {
                    $token = $request->bearerToken();

                    return is_string($token) ? $auth->userForToken($token) : null;
                }

                return $request->hasSession() ? $auth->user() : null;
            }, $app['request'], $app['auth']->createUserProvider());

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/koamishin.php' => config_path('koamishin.php'),
            ], 'koamishin-config');
        }
    }
}

<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Koamishin\Auth\Middleware\RedirectToHostedAuthentication;

class KoamishinServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/koamishin.php', 'koamishin');

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
            );
        });

        $this->app->singleton(KoamishinManagementClient::class, function ($app) {
            $config = $app['config']->get('koamishin');

            return new KoamishinManagementClient(
                portalUrl: (string) ($config['portal_url'] ?? ''),
                clientId: (string) ($config['management_client_id'] ?? ''),
                clientSecret: (string) ($config['management_client_secret'] ?? ''),
            );
        });
    }

    public function boot(): void
    {
        $this->app['router']->pushMiddlewareToGroup('web', RedirectToHostedAuthentication::class);

        if (! $this->app->routesAreCached()) {
            Route::middleware('web')->group(function (): void {
                Route::get('/login', [RedirectToHostedAuthentication::class, 'fallback'])->name('login');
                Route::get('/register', [RedirectToHostedAuthentication::class, 'fallback'])->name('register');
            });
        }

        Auth::viaRequest('koamishin', function (Request $request): ?KoamishinUser {
            $auth = $this->app->make(KoamishinAuth::class);
            if ($request->headers->has('Authorization')) {
                $token = $request->bearerToken();

                return is_string($token) ? $auth->userForToken($token) : null;
            }

            return $request->hasSession() ? $auth->user() : null;
        });

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/koamishin.php' => config_path('koamishin.php'),
            ], 'koamishin-config');
        }
    }
}

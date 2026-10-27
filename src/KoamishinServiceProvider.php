<?php

declare(strict_types=1);

namespace Koamishin\Auth;

use Illuminate\Support\ServiceProvider;

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
            );
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/koamishin.php' => config_path('koamishin.php'),
            ], 'koamishin-config');
        }
    }
}

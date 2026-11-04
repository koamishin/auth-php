<?php

declare(strict_types=1);

namespace Koamishin\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Koamishin\Auth\KoamishinRequestGuard;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

class EnsureSetupIntegrity
{
    public function handle(Request $request, Closure $next): Response
    {
        $guard = config('auth.guards.koamishin');
        if (! is_array($guard) || ($guard['driver'] ?? null) !== 'koamishin') {
            throw new RuntimeException('The koamishin guard must use the koamishin driver while setup is enabled.');
        }

        if (! Auth::guard('koamishin') instanceof KoamishinRequestGuard) {
            throw new RuntimeException('The koamishin driver must resolve to the SDK guard while setup is enabled.');
        }

        if ((app('router')->getMiddleware()['koamishin.auth'] ?? null) !== AuthenticateKoamishin::class) {
            throw new RuntimeException('The koamishin.auth middleware alias must reference the SDK middleware.');
        }

        if (config('koamishin-setup.migrate_hosted_routes') !== true) {
            app('router')->pushMiddlewareToGroup('web', RedirectToHostedAuthentication::class);
        }

        return $next($request);
    }
}

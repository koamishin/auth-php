<?php

declare(strict_types=1);

namespace Koamishin\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Koamishin\Auth\KoamishinAuth;
use Symfony\Component\HttpFoundation\Response;

class RedirectToHostedAuthentication
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('koamishin.hosted_auth_routes', true)
            || ! filled(config('koamishin.client_id'))
            || ! $request->is('login', 'register')) {
            return $next($request);
        }

        if ($request->isMethod('POST')) {
            abort(405, 'Authentication is handled by the Koamishin Portal.');
        }

        if (! $request->isMethod('GET')) {
            return $next($request);
        }

        $returnTo = $request->query('return_to', config('koamishin.hosted_return_to'));
        $returnTo = is_string($returnTo) ? $returnTo : null;
        $auth = app(KoamishinAuth::class);
        $url = $request->is('register')
            ? $auth->getRegistrationUrl($returnTo)
            : $auth->getLoginUrl($returnTo);

        return redirect()->away($url);
    }

    public function fallback(): never
    {
        abort(404);
    }
}

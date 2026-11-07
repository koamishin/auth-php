<?php

declare(strict_types=1);

namespace Koamishin\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Koamishin\Auth\Facades\Koamishin;
use Koamishin\Auth\SessionTokenVerifier;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateWithKoamishin
{
    /**
     * Handle an incoming request.
     *
     * Bearer session tokens are verified offline against the cached key set;
     * any other bearer token is revalidated against Koamishin Auth as before.
     */
    public function handle(Request $request, Closure $next, ?string $role = null): Response
    {
        if ($request->headers->has('Authorization')) {
            $bearer = (string) $request->bearerToken();
            $user = SessionTokenVerifier::isSessionToken($bearer)
                ? Koamishin::userForSessionToken($bearer)
                : Koamishin::userForToken($bearer);
        } else {
            $user = Koamishin::user();
        }

        if (! $user) {
            if ($request->expectsJson()) {
                return response()->json(['message' => 'Unauthenticated.'], 401);
            }

            return redirect()->away(Koamishin::getLoginUrl($request->getRequestUri()));
        }

        if ($role && ! $user->hasRole($role)) {
            if ($request->expectsJson()) {
                return response()->json(['message' => 'Forbidden.'], 403);
            }

            abort(403, 'Unauthorized.');
        }

        $request->setUserResolver(fn (?string $guard = null) => $guard === null || $guard === 'koamishin'
            ? $user
            : Auth::guard($guard)->user());

        return $next($request);
    }
}

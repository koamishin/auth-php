<?php

declare(strict_types=1);

namespace Koamishin\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Koamishin\Auth\Facades\Koamishin;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateWithKoamishin
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next, ?string $role = null): Response
    {
        $user = $request->headers->has('Authorization')
            ? Koamishin::userForToken((string) $request->bearerToken())
            : Koamishin::user();

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

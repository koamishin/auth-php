<?php

declare(strict_types=1);

namespace Koamishin\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Koamishin\Auth\Facades\Koamishin;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateWithKoamishin
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next, ?string $role = null): Response
    {
        $user = Koamishin::user();

        if (! $user) {
            if ($request->expectsJson()) {
                return response()->json(['message' => 'Unauthenticated.'], 401);
            }

            return redirect()->away(Koamishin::getLoginUrl($request->fullUrl()));
        }

        if ($role && ! $user->hasRole($role)) {
            if ($request->expectsJson()) {
                return response()->json(['message' => 'Forbidden.'], 403);
            }

            abort(403, 'Unauthorized.');
        }

        return $next($request);
    }
}

<?php

declare(strict_types=1);

namespace Koamishin\Auth\Middleware;

use Closure;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Http\Request;
use InvalidArgumentException;

class AuthenticateKoamishin extends Authenticate
{
    public function handle($request, Closure $next, ...$guards): mixed
    {
        if ($guards !== []) {
            throw new InvalidArgumentException('The koamishin.auth middleware does not accept guard parameters.');
        }

        return parent::handle($request, $next, 'koamishin');
    }

    protected function redirectTo(Request $request): ?string
    {
        return route('koamishin.login');
    }
}

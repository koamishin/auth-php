<?php

declare(strict_types=1);

namespace Koamishin\Auth\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Koamishin\Auth\KoamishinAuth;

class AuthenticationController
{
    public function login(Request $request, KoamishinAuth $auth): RedirectResponse
    {
        $returnTo = $request->query('return_to', config('koamishin.hosted_return_to'));

        return redirect()->away($auth->getLoginUrl(is_string($returnTo) ? $returnTo : null));
    }

    public function register(Request $request, KoamishinAuth $auth): RedirectResponse
    {
        $returnTo = $request->query('return_to', config('koamishin.hosted_return_to'));

        return redirect()->away($auth->getRegistrationUrl(is_string($returnTo) ? $returnTo : null));
    }

    public function callback(Request $request, KoamishinAuth $auth): RedirectResponse
    {
        if ($request->query('error')) {
            abort(403, 'Sign-in was not completed.');
        }

        $input = $request->validate([
            'code' => ['required', 'string'],
            'state' => ['required', 'string'],
        ]);

        try {
            $auth->handleCallback($input['code'], $input['state']);
        } catch (InvalidArgumentException) {
            abort(403, 'Invalid or expired sign-in request.');
        }

        return redirect()->to($auth->consumeReturnTo('/'));
    }

    public function logout(KoamishinAuth $auth): RedirectResponse
    {
        $auth->logout();

        return redirect('/');
    }
}

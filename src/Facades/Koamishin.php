<?php

declare(strict_types=1);

namespace Koamishin\Auth\Facades;

use Illuminate\Support\Facades\Facade;
use Koamishin\Auth\KoamishinAuth;

/**
 * @method static bool isConfigured()
 * @method static string resolvedEnvironment()
 * @method static string getLoginUrl(?string $returnTo = null)
 * @method static string getRegistrationUrl(?string $returnTo = null)
 * @method static \Koamishin\Auth\KoamishinUser handleCallback(string $code, string $state)
 * @method static \Koamishin\Auth\KoamishinUser|null user()
 * @method static \Koamishin\Auth\KoamishinUser|null userForToken(string $accessToken)
 * @method static \Koamishin\Auth\SessionToken sessionToken()
 * @method static \Koamishin\Auth\KoamishinUser|null userForSessionToken(string $token)
 * @method static bool check()
 * @method static void logout()
 * @method static string consumeReturnTo(string $default = '/')
 *
 * @see KoamishinAuth
 */
class Koamishin extends Facade
{
    #[\Override]
    protected static function getFacadeAccessor(): string
    {
        return KoamishinAuth::class;
    }
}

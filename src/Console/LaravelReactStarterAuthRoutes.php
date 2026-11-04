<?php

declare(strict_types=1);

namespace Koamishin\Auth\Console;

final class LaravelReactStarterAuthRoutes
{
    private const STOCK = <<<'SOURCE'
<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;
use App\Http\Controllers\Auth\ConfirmablePasswordController;
use App\Http\Controllers\Auth\EmailVerificationNotificationController;
use App\Http\Controllers\Auth\EmailVerificationPromptController;
use App\Http\Controllers\Auth\NewPasswordController;
use App\Http\Controllers\Auth\PasswordResetLinkController;
use App\Http\Controllers\Auth\RegisteredUserController;
use App\Http\Controllers\Auth\VerifyEmailController;
use Illuminate\Support\Facades\Route;

Route::middleware('guest')->group(function () {
    Route::get('register', [RegisteredUserController::class, 'create'])
        ->name('register');

    Route::post('register', [RegisteredUserController::class, 'store']);

    Route::get('login', [AuthenticatedSessionController::class, 'create'])
        ->name('login');

    Route::post('login', [AuthenticatedSessionController::class, 'store']);

    Route::get('forgot-password', [PasswordResetLinkController::class, 'create'])
        ->name('password.request');

    Route::post('forgot-password', [PasswordResetLinkController::class, 'store'])
        ->name('password.email');

    Route::get('reset-password/{token}', [NewPasswordController::class, 'create'])
        ->name('password.reset');

    Route::post('reset-password', [NewPasswordController::class, 'store'])
        ->name('password.store');
});

Route::middleware('auth')->group(function () {
    Route::get('verify-email', EmailVerificationPromptController::class)
        ->name('verification.notice');

    Route::get('verify-email/{id}/{hash}', VerifyEmailController::class)
        ->middleware(['signed', 'throttle:6,1'])
        ->name('verification.verify');

    Route::post('email/verification-notification', [EmailVerificationNotificationController::class, 'store'])
        ->middleware('throttle:6,1')
        ->name('verification.send');

    Route::get('confirm-password', [ConfirmablePasswordController::class, 'show'])
        ->name('password.confirm');

    Route::post('confirm-password', [ConfirmablePasswordController::class, 'store']);

    Route::post('logout', [AuthenticatedSessionController::class, 'destroy'])
        ->name('logout');
});
SOURCE;

    private const REPLACEMENT = <<<'SOURCE'
<?php

use Illuminate\Support\Facades\Route;
use Koamishin\Auth\Http\Controllers\AuthenticationController;

// Replaced by koamishin:setup for the unmodified Laravel React Starter Kit routes.
Route::get('register', [AuthenticationController::class, 'register'])
    ->name('register');

Route::get('login', [AuthenticationController::class, 'login'])
    ->name('login');

Route::redirect('forgot-password', '/koamishin/login')
    ->name('password.request');

Route::redirect('reset-password/{token}', '/koamishin/login')
    ->name('password.reset');

Route::post('logout', [AuthenticationController::class, 'logout'])
    ->name('logout');
SOURCE;

    public static function isStock(string $contents): bool
    {
        return self::normalize($contents) === self::normalize(self::STOCK."\n");
    }

    public static function isReplacement(string $contents): bool
    {
        return self::normalize($contents) === self::normalize(self::REPLACEMENT."\n");
    }

    public static function replacement(string $existingContents): string
    {
        $lineEnding = str_contains($existingContents, "\r\n") ? "\r\n" : "\n";

        return str_replace("\n", $lineEnding, self::normalize(self::REPLACEMENT."\n"));
    }

    private static function normalize(string $contents): string
    {
        return str_replace(["\r\n", "\r"], "\n", $contents);
    }
}

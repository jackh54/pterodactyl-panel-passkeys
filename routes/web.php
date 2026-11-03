<?php

use Illuminate\Support\Facades\Route;
use PanelPasskeys\Auth\PasskeyLoginController;

// /extensions/panel-passkeys/passkey/... (web group: session, cookies, CSRF). Signing in with a passkey,
// for guests only and under the same per-IP limiter as the panel's login endpoints. Failures count
// towards the normal login lockout.
Route::middleware(['guest', 'throttle:authentication'])->group(function (): void {
    Route::post('/passkey/options', [PasskeyLoginController::class, 'options'])->name('passkey.options');
    Route::post('/passkey/login', [PasskeyLoginController::class, 'login'])->name('passkey.login');
});

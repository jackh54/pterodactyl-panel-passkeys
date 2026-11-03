<?php

use Illuminate\Support\Facades\Route;
use PanelPasskeys\Auth\PasskeyController;
use PanelPasskeys\Auth\RequirePanelSession;

// /api/client/extensions/panel-passkeys/passkeys... (api group + 2FA + client-api + throttle:api.client).
// The signed-in user's own passkeys. Panel session only: an API key can neither list nor change
// them (a passkey ceremony needs the session-bound challenge anyway). Adding and removing also
// need the account password.
Route::prefix('/passkeys')
    ->middleware(RequirePanelSession::class)
    ->group(function (): void {
        Route::get('/', [PasskeyController::class, 'index'])->name('passkeys.index');
        Route::post('/options', [PasskeyController::class, 'options'])->name('passkeys.options');
        Route::post('/dismiss-prompt', [PasskeyController::class, 'dismissPrompt'])->name('passkeys.dismiss-prompt');
        Route::post('/', [PasskeyController::class, 'store'])->name('passkeys.store');
        Route::delete('/{passkey}', [PasskeyController::class, 'destroy'])->whereNumber('passkey')->name('passkeys.destroy');
    });

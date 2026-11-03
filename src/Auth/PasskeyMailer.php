<?php

namespace PanelPasskeys\Auth;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Mail\Message;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use PanelPasskeys\Settings;
use Pterodactyl\Models\User;
use Throwable;

/**
 * Security notice to the account owner when a passkey is added or removed. Sent after the
 * response has gone out (not queued), and a mail failure never fails the request. Off when the
 * admin turns "Email on passkey changes" off.
 */
final class PasskeyMailer
{
    public function __construct(private readonly Application $app) {}

    public function send(User $user, string $message): void
    {
        if (! Settings::notifyEmail()) {
            return;
        }

        $email = (string) $user->email;
        $userId = $user->id;
        $panel = (string) config('app.name', 'Pterodactyl');
        $url = rtrim((string) config('app.url'), '/').'/account';

        $this->app->terminating(static function () use ($email, $userId, $panel, $url, $message): void {
            try {
                Mail::raw(
                    "{$message}\n\nPanel: {$panel}\n\nIf this was not you, sign in at {$url}, remove the passkey, change your password and contact an administrator.",
                    fn (Message $m) => $m->to($email)->subject("{$panel}: passkey change on your account")
                );
            } catch (Throwable $e) {
                Log::warning('Panel Passkeys: notification email failed', ['user' => $userId, 'error' => $e->getMessage()]);
            }
        });
    }
}

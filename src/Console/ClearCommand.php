<?php

namespace PanelPasskeys\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Pterodactyl\Models\User;
use PanelPasskeys\Tables;

/**
 * Lists or removes an account's passkeys, for a user who lost every device that held one. The user
 * can still sign in with their password (and two-step code), then add a new passkey.
 *
 *   php artisan panel-passkeys:clear <user>            list the account's passkeys and ask before removing them
 *   php artisan panel-passkeys:clear <user> --force    remove them without asking
 *
 * <user> is a user id, username or email address.
 */
class ClearCommand extends Command
{
    protected $signature = 'panel-passkeys:clear {user : User id, username or email} {--force : Remove without asking}';

    protected $description = "List and remove an account's passkeys.";

    public function handle(): int
    {
        $needle = trim((string) $this->argument('user'));
        // Usernames may be all digits, so a number is matched as an id and as a username.
        $users = User::query()
            ->where(fn ($q) => $q->where('username', $needle)->orWhere('email', $needle)
                ->when(ctype_digit($needle), fn ($q) => $q->orWhere('id', (int) $needle)))
            ->limit(2)
            ->get();

        if ($users->count() !== 1) {
            $this->error($users->isEmpty()
                ? "No user matches \"{$needle}\"."
                : "\"{$needle}\" matches more than one user (an id and a username). Use the email address instead.");

            return self::FAILURE;
        }
        $user = $users->first();

        $passkeys = DB::table(Tables::passkeys())->where('user_id', $user->id)->orderBy('id')->get(['id', 'name', 'created_at', 'last_used_at']);
        $this->line("{$user->username} <{$user->email}> (id {$user->id}): {$passkeys->count()} passkey(s)");
        if ($passkeys->isEmpty()) {
            return self::SUCCESS;
        }

        $this->table(['id', 'name', 'added', 'last used'], $passkeys->map(fn (object $p): array => [
            $p->id, $p->name, (string) $p->created_at, (string) ($p->last_used_at ?? 'never'),
        ])->all());

        if (! $this->option('force') && ! $this->confirm('Remove all of them?')) {
            $this->line('Nothing removed.');

            return self::SUCCESS;
        }

        $removed = DB::table(Tables::passkeys())->where('user_id', $user->id)->delete();
        $this->info("Removed {$removed} passkey(s).");

        return self::SUCCESS;
    }
}

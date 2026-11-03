<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Table names: PANEL_PASSKEYS_TABLE_PREFIX (default ext_passkeys_user_) + passkeys / prefs, as in
     * PanelPasskeys\Tables. The panel runs extension migrations before the extension's classes are
     * autoloadable, so this file repeats the rule.
     */
    private function table(string $name): string
    {
        $prefix = (string) (config('panel-passkeys.table_prefix') ?? env('PANEL_PASSKEYS_TABLE_PREFIX', 'ext_passkeys_user_'));

        return (preg_match('/^[a-z][a-z0-9_]{0,30}$/', $prefix) === 1 ? $prefix : 'ext_passkeys_user_').$name;
    }

    /**
     * WebAuthn passkeys, plus per-user flags (the passkey user handle and the one-time prompt).
     *
     * The table checks make this a no-op over tables an earlier install already created (same layout),
     * and cover a database that has the tables without the migration record.
     */
    public function up(): void
    {
        if (! Schema::hasTable($this->table('passkeys'))) {
            Schema::create($this->table('passkeys'), function (Blueprint $table) {
                $table->increments('id');
                $table->unsignedInteger('user_id');
                $table->string('name', 64);
                // base64url credential id; unique across the whole panel.
                $table->string('credential_id', 512)->unique();
                // PEM encoded public key returned by the authenticator. Public, not a secret.
                $table->text('public_key');
                $table->unsignedBigInteger('sign_count')->default(0);
                $table->string('aaguid', 36)->nullable();
                $table->boolean('backup_eligible')->default(false);
                $table->timestamp('last_used_at')->nullable();
                $table->string('last_used_ip', 45)->nullable();
                $table->timestamps();

                $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
                $table->index('user_id');
            });
        }

        if (! Schema::hasTable($this->table('prefs'))) {
            Schema::create($this->table('prefs'), function (Blueprint $table) {
                $table->unsignedInteger('user_id')->primary();
                // Random, opaque WebAuthn user.id, base64url (never the database id, email or username).
                $table->string('webauthn_user_handle', 64)->unique();
                $table->timestamp('passkey_prompt_dismissed_at')->nullable();
                $table->timestamps();

                $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists($this->table('passkeys'));
        Schema::dropIfExists($this->table('prefs'));
    }
};

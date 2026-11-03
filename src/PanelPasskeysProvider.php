<?php

namespace PanelPasskeys;

use PanelPasskeys\Console\ClearCommand;
use Pterodactyl\Extensions\ExtensionProvider;
use Pterodactyl\Services\Extensions\ExtensionSettingsDefinition;

/**
 * Panel Passkeys: WebAuthn passkey sign-in for the panel.
 *
 * routes/web.php    -> /extensions/panel-passkeys/passkey/{options,login}   (guests: sign in)
 * routes/client.php -> /api/client/extensions/panel-passkeys/passkeys/...   (the signed-in user's passkeys)
 */
class PanelPasskeysProvider extends ExtensionProvider
{
    public const string ID = 'panel-passkeys';

    public const string VERSION = '1.0.0';

    public function register(): void
    {
        $this->mergeConfigFrom($this->extensionPath('resources', 'config', 'panel-passkeys.php'), 'panel-passkeys');
    }

    public function boot(): void
    {
        // The panel also registers this directory when it enables the extension; calling it again changes nothing.
        $this->loadExtensionMigrations();

        $this->registerWebRoutes($this->extensionPath('routes', 'web.php'));
        $this->registerApiRoutes();

        // `panel-passkeys:clear <user>` removes an account's passkeys (a user who lost every device).
        $this->registerCommands([ClearCommand::class]);

        // Admin -> Extensions -> Panel Passkeys.
        $this->registerSettings(new ExtensionSettingsDefinition($this->settings(), Settings::definitions()));

        // Activity log wording for auth:passkey and user:passkey.* (merged into the panel's `activity` group).
        $loader = $this->app->make('translation.loader');
        if (method_exists($loader, 'addPath')) {
            $loader->addPath($this->extensionPath('src', 'lang'));
        }
    }
}

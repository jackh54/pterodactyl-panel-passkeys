<?php

namespace PanelPasskeys;

use Pterodactyl\Services\Extensions\ExtensionRepository;
use Pterodactyl\Services\Extensions\ExtensionSettingDefinition;

/**
 * Admin -> Extensions -> Panel Passkeys. An empty or unreadable value reads as the default.
 */
final class Settings
{
    public const int MAX_LIMIT = 25;

    private const array DEFAULTS = [
        'max_per_user' => 10,
        'dashboard_prompt' => true,
        'notify_email' => true,
    ];

    /** @return list<ExtensionSettingDefinition> */
    public static function definitions(): array
    {
        return [
            ExtensionSettingDefinition::make('max_per_user', 'max_per_user', self::DEFAULTS['max_per_user'], ['nullable', 'integer', 'min:1', 'max:'.self::MAX_LIMIT])
                ->field('number')
                ->label('Passkeys per account')
                ->help('How many passkeys one account may register (1 to '.self::MAX_LIMIT.'). Lowering it keeps existing passkeys; users just cannot add more.')
                ->tab('Passkeys'),
            ExtensionSettingDefinition::make('dashboard_prompt', 'dashboard_prompt', self::DEFAULTS['dashboard_prompt'])
                ->field('toggle')
                ->label('Invite users to add a passkey')
                ->help('A one-time notice above the dashboard for accounts without a passkey. Users can dismiss it; the choice is kept on every device.')
                ->tab('Passkeys'),
            ExtensionSettingDefinition::make('notify_email', 'notify_email', self::DEFAULTS['notify_email'])
                ->field('toggle')
                ->label('Email on passkey changes')
                ->help('Email the account owner when a passkey is added to or removed from their account. Needs working panel mail.')
                ->tab('Passkeys'),
        ];
    }

    public static function maxPerUser(): int
    {
        $value = self::get('max_per_user');

        return is_numeric($value) ? max(1, min(self::MAX_LIMIT, (int) $value)) : self::DEFAULTS['max_per_user'];
    }

    public static function dashboardPrompt(): bool
    {
        return self::bool('dashboard_prompt');
    }

    public static function notifyEmail(): bool
    {
        return self::bool('notify_email');
    }

    private static function bool(string $key): bool
    {
        $value = self::get($key);

        return is_bool($value) ? $value : (filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? self::DEFAULTS[$key]);
    }

    private static function get(string $key): mixed
    {
        try {
            $value = app(ExtensionRepository::class)->settings(PanelPasskeysProvider::ID)->get($key, self::DEFAULTS[$key]);
        } catch (\Throwable) {
            return self::DEFAULTS[$key];
        }

        return $value === null || $value === '' ? self::DEFAULTS[$key] : $value;
    }
}

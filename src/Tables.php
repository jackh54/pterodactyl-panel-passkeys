<?php

namespace PanelPasskeys;

/**
 * Table names. Both tables share one prefix (default `ext_passkeys_user_`), set with
 * PANEL_PASSKEYS_TABLE_PREFIX. Change it only before the first install, or to point the extension
 * at tables an earlier install already filled.
 */
final class Tables
{
    public const string DEFAULT_PREFIX = 'ext_passkeys_user_';

    public static function prefix(): string
    {
        $prefix = (string) config('panel-passkeys.table_prefix', self::DEFAULT_PREFIX);

        return preg_match('/^[a-z][a-z0-9_]{0,30}$/', $prefix) === 1 ? $prefix : self::DEFAULT_PREFIX;
    }

    /** One row per passkey. */
    public static function passkeys(): string
    {
        return self::prefix().'passkeys';
    }

    /** One row per user: the WebAuthn user handle and the dismissed dashboard notice. */
    public static function prefs(): string
    {
        return self::prefix().'prefs';
    }
}

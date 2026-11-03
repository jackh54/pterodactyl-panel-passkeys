<?php

// Merged as config('panel-passkeys.*') by PanelPasskeysProvider::register(). env() is read only here,
// so a cached config still carries the values.
return [
    // Prefix of the two tables ({prefix}passkeys and {prefix}prefs). Leave it alone unless you are
    // pointing the extension at tables an earlier install already created.
    'table_prefix' => env('PANEL_PASSKEYS_TABLE_PREFIX', 'ext_passkeys_user_'),
];

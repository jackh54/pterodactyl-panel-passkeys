<?php

// Merged into the panel's `activity` translation group by PanelPasskeysProvider (translator addPath), so
// the account and admin activity logs describe passkey events like the panel's own.
return [
    'auth' => [
        'passkey' => 'Signed in with the :name passkey',
    ],
    'user' => [
        'passkey' => [
            'create' => 'Added the :name passkey',
            'delete' => 'Removed the :name passkey',
        ],
    ],
];

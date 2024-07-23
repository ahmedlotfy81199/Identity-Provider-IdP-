<?php

return [
    'idp' => [
        'entityId' => env('SAML2_IDP_ENTITYID'),
        'singleSignOnService' => [
            'url' => env('SAML2_IDP_SSO_URL'),
        ],
        'singleLogoutService' => [
            'url' => env('SAML2_IDP_SLO_URL'),
        ],
        'x509cert' => env('SAML2_IDP_x509CERT'),
    ],
    'sp' => [
        'entityId' => env('SAML2_SP_ENTITYID'),
        'assertionConsumerService' => [
            'url' => env('SAML2_SP_ACS_URL'),
        ],
        'singleLogoutService' => [
            'url' => env('SAML2_SP_SLO_URL'),
        ],
        'x509cert' => env('SAML2_SP_x509CERT'),
        'privateKey' => env('SAML2_SP_PRIVATEKEY'),
    ],
];

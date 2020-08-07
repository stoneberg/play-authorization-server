INSERT INTO oauth_client_details (
    client_id,
    resource_ids,
    client_secret,
    "scope",
    authorized_grant_types,
    web_server_redirect_uri,
    authorities,
    access_token_validity,
    refresh_token_validity,
    additional_information,
    autoapprove
 ) VALUES (
    'testClientId',
    null,
    '{bcrypt}$2a$10$t7U/mh4U.NvIlOdyTVvF0.b1NS1r898D4kScQdm17i8sKVTLPH.PC',
    'read,write',
    'authorization_code,refresh_token',
    'http://localhost:8081/oauth2/callback',
    'ROLE_USER',
    36000,
    50000,
    null,
    null
);

INSERT INTO oauth_user (msrl, "name", "password", provider, uid)
VALUES (1, 'stoneberg', '{bcrypt}$2a$10$OvRRX3TxDCfQEK0NA0RC3.zzy52Y3DK9Y78rtgc.t6FPVk/X8xaZu', null, 'stoneberg@gmail.com');

INSERT INTO user_roles (user_msrl, roles)
VALUES (1, 'ROLE_USER');


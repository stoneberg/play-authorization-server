-- Schema for PostgreSQL to use with JdbcTokenStore (Spring Security OAuth2)
-- https://gist.github.com/fernandomantoan/3ff4b90d7e9eae4a5d1e
create table oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(256)
);

create table oauth_client_token (
  token_id VARCHAR(256),
  token bytea,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256)
);

create table oauth_access_token (
  token_id VARCHAR(256),
  token bytea,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256),
  authentication bytea,
  refresh_token VARCHAR(256)
);

create table oauth_refresh_token (
  token_id VARCHAR(256),
  token bytea,
  authentication bytea
);

create table oauth_code (
  code VARCHAR(256), authentication bytea
);

create table oauth_approvals (
  userId VARCHAR(256),
  clientId VARCHAR(256),
  scope VARCHAR(256),
  status VARCHAR(10),
  expiresAt TIMESTAMP,
  lastModifiedAt TIMESTAMP
);


insert into oauth_client_details(client_id, resource_ids,client_secret,scope,authorized_grant_types,web_server_redirect_uri,authorities,access_token_validity,refresh_token_validity,additional_information,autoapprove)
values('testClientId',null,'{bcrypt}$2a$10$t7U/mh4U.NvIlOdyTVvF0.b1NS1r898D4kScQdm17i8sKVTLPH.PC','read,write','authorization_code,refresh_token','http://localhost:8081/oauth2/callback','ROLE_USER',36000,50000,null,null);

----

CREATE	table oauth_user (
	msrl bigserial NOT null,
	name varchar(100) NOT null,
	password varchar(100),
	provider varchar(100),
	uid varchar(50) NOT null,
	primary key (msrl)
);

CREATE table user_roles
	(user_msrl int8 NOT null,roles varchar(255));

ALTER table oauth_user add constraint UK_4qbbm0drubj3be3wtjc3wj5ks unique (uid);
ALTER table user_roles add constraint FKj5j95uhpxypdkynvsjlh5pk2i foreign key (user_msrl) references oauth_user;
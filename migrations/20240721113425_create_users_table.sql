-- +goose Up
create type user_role as enum('user', 'admin');

create table users (
    id bigserial primary key,
    name text not null, 
    password_hash text not null,
    password_confirmed boolean default false,
    email text not null,
    role user_role not null,
    created_at timestamptz default now() not null,
    updated_at timestamptz
);

create unique index if not exists users_name_idx on "users"(name);

-- +goose Down
drop table "users";
drop type user_role;

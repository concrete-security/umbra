-- Enable useful extensions ----------------------------------------------------
create extension if not exists "pgcrypto";
create extension if not exists "citext";

-- Waitlist requests -----------------------------------------------------------
do $$
begin
  if not exists (
    select 1
    from pg_type t
    join pg_namespace n on n.oid = t.typnamespace
    where t.typname = 'waitlist_status'
      and n.nspname = 'public'
  ) then
    create type public.waitlist_status as enum ('requested', 'contacted', 'invited', 'activated', 'archived');
  end if;
end
$$;

create table if not exists public.waitlist_requests (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default timezone('utc', now()),
  email citext not null unique,
  company text,
  use_case text,
  status public.waitlist_status not null default 'requested',
  notes text,
  priority integer,
  last_contacted_at timestamptz,
  supabase_user_id uuid references auth.users (id) on delete set null,
  activation_sent_at timestamptz,
  activation_link text,
  activated_at timestamptz,
  metadata jsonb
);

alter table public.waitlist_requests
  add column if not exists company text,
  add column if not exists use_case text,
  add column if not exists status public.waitlist_status not null default 'requested',
  add column if not exists notes text,
  add column if not exists priority integer,
  add column if not exists last_contacted_at timestamptz,
  add column if not exists supabase_user_id uuid references auth.users (id) on delete set null,
  add column if not exists activation_sent_at timestamptz,
  add column if not exists activation_link text,
  add column if not exists activated_at timestamptz,
  add column if not exists metadata jsonb;

create index if not exists waitlist_requests_created_at_idx
  on public.waitlist_requests (created_at desc);

create index if not exists waitlist_requests_status_idx
  on public.waitlist_requests (status);

create index if not exists waitlist_requests_user_idx
  on public.waitlist_requests (supabase_user_id)
  where supabase_user_id is not null;

-- Security policies -----------------------------------------------------------
alter table public.waitlist_requests enable row level security;

drop policy if exists "allow service role access to waitlist requests" on public.waitlist_requests;
create policy "allow service role access to waitlist requests"
  on public.waitlist_requests
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

-- Waitlist activation trigger -------------------------------------------------
create or replace function public.handle_waitlist_activation()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  waitlist_entry public.waitlist_requests%rowtype;
  merged_roles jsonb;
  app_meta jsonb;
  user_meta jsonb;
  now_utc timestamptz := timezone('utc', now());
begin
  if TG_OP = 'UPDATE' and (OLD.email_confirmed_at is not distinct from NEW.email_confirmed_at) then
    return NEW;
  end if;

  if NEW.email_confirmed_at is null then
    return NEW;
  end if;

  select *
    into waitlist_entry
    from public.waitlist_requests
   where email = NEW.email::citext
     and status = 'invited'
   limit 1;

  if not found then
    return NEW;
  end if;

  update public.waitlist_requests
     set status = 'activated',
         supabase_user_id = NEW.id,
         activated_at = coalesce(activated_at, now_utc),
         last_contacted_at = coalesce(last_contacted_at, now_utc),
         metadata = coalesce(metadata, '{}'::jsonb) || jsonb_build_object(
           'activated_via',
           'auth_trigger',
           'activated_at',
           now_utc
         )
   where id = waitlist_entry.id;

  app_meta := coalesce(NEW.raw_app_meta_data, '{}'::jsonb);

  merged_roles := (
    select coalesce(jsonb_agg(role order by role), jsonb_build_array('member'))
    from (
      select distinct role
      from (
        select jsonb_array_elements_text(coalesce(app_meta->'roles', '[]'::jsonb)) as role
        union all
        select 'member'
      ) roles
    ) distinct_roles
  );

  app_meta := jsonb_set(app_meta, '{roles}', merged_roles, true);
  app_meta := jsonb_set(app_meta, '{waitlist_request_id}', to_jsonb(waitlist_entry.id::text), true);
  NEW.raw_app_meta_data := app_meta;

  user_meta := coalesce(NEW.raw_user_meta_data, '{}'::jsonb);

  if waitlist_entry.company is not null then
    user_meta := jsonb_set(user_meta, '{company}', to_jsonb(waitlist_entry.company), true);
  end if;

  if waitlist_entry.use_case is not null then
    user_meta := jsonb_set(user_meta, '{use_case}', to_jsonb(waitlist_entry.use_case), true);
  end if;

  NEW.raw_user_meta_data := user_meta;

  return NEW;
end;
$$;

drop trigger if exists promote_invited_waitlist_user on auth.users;
create trigger promote_invited_waitlist_user
before insert or update of email_confirmed_at on auth.users
for each row
when (NEW.email_confirmed_at is not null)
execute function public.handle_waitlist_activation();

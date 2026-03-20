-- ============================================================
-- Eclipse Estimator — Supabase Schema
-- Run this in your Supabase SQL Editor (supabase.com → project → SQL Editor)
-- ============================================================

-- 1. Dealers table
create table if not exists public.dealers (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  code text unique not null,
  created_at timestamptz default now()
);

-- 2. Profiles table (extends Supabase auth.users)
create table if not exists public.profiles (
  id uuid references auth.users on delete cascade primary key,
  email text not null unique,
  full_name text not null default '',
  role text not null default 'pending' check (role in ('admin','dealer','designer','pending')),
  dealer_id uuid references public.dealers(id),
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- 3. Quotes table
create table if not exists public.quotes (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  name text not null default 'Untitled Project',
  data jsonb not null default '{}',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- 4. Indexes for performance
create index if not exists idx_quotes_user_id on public.quotes(user_id);
create index if not exists idx_quotes_updated_at on public.quotes(updated_at);
create index if not exists idx_profiles_dealer on public.profiles(dealer_id);
create index if not exists idx_profiles_role on public.profiles(role);

-- 5. Enable Row Level Security
alter table public.dealers enable row level security;
alter table public.profiles enable row level security;
alter table public.quotes enable row level security;

-- 6. RLS Policies — Profiles
create policy "Users can view own profile" on public.profiles
  for select using (auth.uid() = id);

create policy "Admins can view all profiles" on public.profiles
  for select using (
    exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

create policy "Users can update own profile" on public.profiles
  for update using (auth.uid() = id)
  with check (auth.uid() = id and role = old.role);  -- prevent self-role-change

create policy "Admins can update all profiles" on public.profiles
  for update using (
    exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

create policy "Allow profile creation" on public.profiles
  for insert with check (auth.uid() = id);

-- 7. RLS Policies — Quotes
create policy "Users can view own quotes" on public.quotes
  for select using (user_id = auth.uid());

create policy "Users can insert own quotes" on public.quotes
  for insert with check (user_id = auth.uid());

create policy "Users can update own quotes" on public.quotes
  for update using (user_id = auth.uid());

create policy "Users can delete own quotes" on public.quotes
  for delete using (user_id = auth.uid());

create policy "Admins can view all quotes" on public.quotes
  for select using (
    exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

-- 8. RLS Policies — Dealers
create policy "Anyone can view dealers" on public.dealers
  for select using (auth.role() = 'authenticated');

create policy "Admins can manage dealers" on public.dealers
  for all using (
    exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
  );

-- 9. Auto-create profile on signup with role assignment
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, full_name, role)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    case
      when new.email in ('gillian@pinnaclesales.biz', 'ben@pinnaclesales.biz') then 'admin'
      else 'pending'
    end
  );
  return new;
end;
$$ language plpgsql security definer;

-- Drop old trigger if exists and create new one
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- 10. Update updated_at timestamp on changes
create or replace function public.update_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists quotes_updated_at on public.quotes;
drop trigger if exists profiles_updated_at on public.profiles;

create trigger quotes_updated_at before update on public.quotes
  for each row execute procedure public.update_updated_at();

create trigger profiles_updated_at before update on public.profiles
  for each row execute procedure public.update_updated_at();

-- 11. Grant permissions (adjust as needed for your setup)
grant usage on schema public to authenticated;
grant all on public.profiles to authenticated;
grant all on public.quotes to authenticated;
grant all on public.dealers to authenticated;

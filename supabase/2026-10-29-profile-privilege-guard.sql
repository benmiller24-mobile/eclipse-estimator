-- =====================================================================
-- Eclipse Estimator — profile privilege guard  (2026-10-29)
-- Run once in Supabase → SQL Editor for project rljpgudmvbaocomktone.
-- Safe to re-run.
--
-- WHY: the live "Users can update own profile" policy has no WITH CHECK
-- and there was no guard trigger, so any signed-in user (including a
-- brand-new self-signup with role 'pending') could
--   update profiles set role = 'admin' where id = auth.uid();
-- and then read every quote and every dealer's discount. The original
-- schema tried `role = old.role` in a WITH CHECK, which is not valid in an
-- RLS policy, so that protection never existed.
--
-- WHAT: a BEFORE UPDATE trigger rejects changes to role / dealer_id /
-- discount_pct / email by any signed-in non-admin. A BEFORE INSERT trigger
-- forces self-created profile rows to 'pending' with no dealer/discount.
-- Admin-panel updates (is_admin()) still work, and so do SQL-editor and
-- service-role updates (no auth.uid()).
-- =====================================================================

create or replace function public.prevent_profile_privilege_escalation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is not null and not public.is_admin() then
    if new.role is distinct from old.role then
      raise exception 'Only admins can change profile roles' using errcode = '42501';
    end if;
    if new.dealer_id is distinct from old.dealer_id then
      raise exception 'Only admins can change dealer assignment' using errcode = '42501';
    end if;
    if new.discount_pct is distinct from old.discount_pct then
      raise exception 'Only admins can change discount' using errcode = '42501';
    end if;
    if new.email is distinct from old.email then
      raise exception 'Email is managed by authentication' using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists profiles_privilege_guard on public.profiles;
create trigger profiles_privilege_guard
  before update on public.profiles
  for each row execute function public.prevent_profile_privilege_escalation();

create or replace function public.guard_profile_insert()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- The signup trigger (handle_new_user) runs with no auth.uid(), so it is
  -- unaffected. A client inserting its own row cannot self-assign privileges.
  if auth.uid() is not null and not public.is_admin() then
    new.role := 'pending';
    new.dealer_id := null;
    new.discount_pct := null;
  end if;
  return new;
end;
$$;

drop trigger if exists profiles_insert_guard on public.profiles;
create trigger profiles_insert_guard
  before insert on public.profiles
  for each row execute function public.guard_profile_insert();

-- Supabase security-advisor hygiene
alter function public.handle_new_user() set search_path = public;
alter function public.update_updated_at() set search_path = public;
revoke execute on function public.handle_new_user() from public, anon, authenticated;
revoke execute on function public.prevent_profile_privilege_escalation() from public, anon, authenticated;
revoke execute on function public.guard_profile_insert() from public, anon, authenticated;
revoke execute on function public.get_my_role() from public, anon;

-- Audit: anyone who already escalated themselves shows up here.
-- Every admin should be a @pinnaclesales.biz address.
select p.email, p.role, p.updated_at
from public.profiles p
where p.role = 'admin' and lower(p.email) not like '%@pinnaclesales.biz';

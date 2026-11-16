-- 請購系統 schema(貼到 Supabase SQL Editor 執行)
-- 另需:Authentication → Providers → Email 啟用;測試期可關閉 "Confirm email"

-- 使用者資料(對應 auth.users)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default '',
  role text not null default 'user' check (role in ('user','admin')),
  created_at timestamptz not null default now()
);

-- 註冊時自動建立 profile(role 一律 user,不信任前端傳入)
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name)
  values (new.id, coalesce(new.raw_user_meta_data->>'name', split_part(new.email,'@',1)));
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

create or replace function public.is_admin()
returns boolean language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- 請購單
create table if not exists public.purchase_requests (
  id bigint generated always as identity primary key,
  case_no text not null unique,                       -- 購案編號
  amount numeric(12,0) not null check (amount >= 0),  -- 金額
  item text not null default '',                      -- 品名/用途
  sent_date date,                                     -- 送出日期
  status text not null default '待送出'
    check (status in ('待送出','已送出','已核准','已駁回')),
  created_by uuid not null default auth.uid() references public.profiles(id),
  created_at timestamptz not null default now()
);
create index if not exists purchase_requests_created_by_idx on public.purchase_requests(created_by);

alter table public.profiles enable row level security;
alter table public.purchase_requests enable row level security;

-- profiles:本人或管理員可讀;不開放前端修改(升管理員請用 SQL)
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select
  using (id = auth.uid() or public.is_admin());

-- purchase_requests
drop policy if exists pr_select on public.purchase_requests;
create policy pr_select on public.purchase_requests for select
  using (created_by = auth.uid() or public.is_admin());

drop policy if exists pr_insert on public.purchase_requests;
create policy pr_insert on public.purchase_requests for insert
  with check (created_by = auth.uid() and status in ('待送出','已送出'));

-- 一般使用者只能改自己「待送出/已駁回」的單,且不能自行核准
drop policy if exists pr_update_own on public.purchase_requests;
create policy pr_update_own on public.purchase_requests for update
  using (created_by = auth.uid() and status in ('待送出','已駁回'))
  with check (created_by = auth.uid() and status in ('待送出','已送出'));

drop policy if exists pr_update_admin on public.purchase_requests;
create policy pr_update_admin on public.purchase_requests for update
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists pr_delete_own on public.purchase_requests;
create policy pr_delete_own on public.purchase_requests for delete
  using ((created_by = auth.uid() and status = '待送出') or public.is_admin());

-- 設定管理員(把 email 換成你的):
-- update public.profiles set role = 'admin'
--   where id = (select id from auth.users where email = 'you@example.com');

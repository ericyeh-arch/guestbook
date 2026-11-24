-- 請購系統 schema(貼到 Supabase SQL Editor 執行)
-- 另需:Authentication → Providers → Email 啟用,並關閉 "Allow new users to sign up"(帳號由管理員建立)

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

-- 表的存取權限(此專案不會自動授權給 authenticated;實際資料範圍由上面的 RLS 控制)
grant usage on schema public to authenticated;
grant select on public.profiles to authenticated;
grant select, insert, update, delete on public.purchase_requests to authenticated;

-- ============================================================
-- 請購帳務表(對應 eric-acc.xlsx「工作表」欄位)
-- 日期欄位沿用民國年 7 碼文字(例:1151102),與 Excel 一致
-- ============================================================
create table if not exists public.acc_ledger (
  id bigint generated always as identity primary key,
  year int,                          -- 請購年度
  handler text not null default '',  -- 承辦人
  method text not null default '',   -- 請購方式
  provided_date text,                -- 請購提供日期
  stamp_date text,                   -- 請購或蓋章日期
  expect_date text,                  -- 預計核銷日期
  case_no text not null unique,      -- 購案編號
  category text,                     -- 購案類別
  amount numeric(12,0) not null default 0 check (amount >= 0), -- 採購總金額
  plan_no text,                      -- 計畫編號
  fund_use text,                     -- 經費用途
  reason text not null default '',   -- 採購原因
  progress text not null default '未審', -- 請購進度
  audit_date text,                   -- 主計室購案審核日期
  invoice_date text,                 -- 發票日期
  paid_date text,                    -- 核銷(蓋章)日期
  voucher_no text,                   -- 傳票號
  note text,                         -- 備註
  created_by uuid not null default auth.uid() references public.profiles(id),
  created_at timestamptz not null default now()
);
create index if not exists acc_ledger_created_by_idx on public.acc_ledger(created_by);

alter table public.acc_ledger enable row level security;

drop policy if exists acc_select on public.acc_ledger;
create policy acc_select on public.acc_ledger for select
  using (created_by = auth.uid() or public.is_admin());
drop policy if exists acc_insert on public.acc_ledger;
create policy acc_insert on public.acc_ledger for insert
  with check (created_by = auth.uid());
drop policy if exists acc_update on public.acc_ledger;
create policy acc_update on public.acc_ledger for update
  using (created_by = auth.uid() or public.is_admin())
  with check (created_by = auth.uid() or public.is_admin());
drop policy if exists acc_delete on public.acc_ledger;
create policy acc_delete on public.acc_ledger for delete
  using (created_by = auth.uid() or public.is_admin());

grant select, insert, update, delete on public.acc_ledger to authenticated;

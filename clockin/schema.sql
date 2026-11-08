-- 工讀生打卡系統 | 在 Supabase SQL Editor 執行
create extension if not exists pgcrypto with schema extensions;

-- ========== 資料表 ==========
create table if not exists public.workers (
  id bigint generated always as identity primary key,
  name text not null unique check (char_length(name) between 1 and 30),
  pin_hash text not null,
  active boolean not null default true,
  failed_attempts int not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.punches (
  id bigint generated always as identity primary key,
  worker_id bigint not null references public.workers(id) on delete cascade,
  kind text not null check (kind in ('in', 'out')),
  punched_at timestamptz not null default now(),
  ip text,
  manual boolean not null default false,  -- 管理員補登
  note text
);
alter table public.punches add column if not exists manual boolean not null default false;
alter table public.punches add column if not exists note text;
create index if not exists punches_worker_time on public.punches (worker_id, punched_at desc);

create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

-- ========== 權限:匿名完全不能直接碰資料表 ==========
alter table public.workers enable row level security;
alter table public.punches enable row level security;
alter table public.admins  enable row level security;

create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid())
$$;

drop policy if exists workers_admin on public.workers;
drop policy if exists punches_admin on public.punches;
create policy workers_admin on public.workers for all to authenticated
  using (public.is_admin()) with check (public.is_admin());
create policy punches_admin on public.punches for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

revoke all on public.workers, public.punches, public.admins from anon, authenticated;
grant select, insert, update, delete on public.workers, public.punches to authenticated;

-- ========== 打卡頁用的函式(匿名可呼叫) ==========
-- 上班超過 12 小時未下班 = 視為漏打下班(missed)
drop function if exists public.list_workers();
create function public.list_workers()
returns table (id bigint, name text, clocked_in boolean, missed boolean)
language sql security definer set search_path = public as $$
  select w.id, w.name,
         coalesce(l.kind = 'in' and now() - l.punched_at <= interval '12 hours', false),
         coalesce(l.kind = 'in' and now() - l.punched_at >  interval '12 hours', false)
  from public.workers w
  left join lateral (
    select p.kind, p.punched_at from public.punches p
    where p.worker_id = w.id order by p.punched_at desc, p.id desc limit 1
  ) l on true
  where w.active order by w.name
$$;

create or replace function public.punch(p_worker_id bigint, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  w public.workers; last_p public.punches; new_kind text;
  h json; v_ip text; v_ts timestamptz := now(); v_missed boolean;
begin
  select * into w from public.workers where id = p_worker_id and active;
  if not found then
    return json_build_object('ok', false, 'error', '找不到此工讀生');
  end if;
  if w.locked_until is not null and w.locked_until > v_ts then
    return json_build_object('ok', false, 'error', 'PIN 錯誤次數過多,請 5 分鐘後再試');
  end if;
  if w.pin_hash <> crypt(coalesce(p_pin, ''), w.pin_hash) then
    update public.workers set
      failed_attempts = case when failed_attempts + 1 >= 5 then 0 else failed_attempts + 1 end,
      locked_until = case when failed_attempts + 1 >= 5 then v_ts + interval '5 minutes' else null end
    where id = w.id;
    return json_build_object('ok', false, 'error', 'PIN 錯誤');
  end if;

  update public.workers set failed_attempts = 0, locked_until = null where id = w.id;

  select * into last_p from public.punches
    where worker_id = w.id order by punched_at desc, id desc limit 1;
  if found and v_ts - last_p.punched_at < interval '10 seconds' then
    return json_build_object('ok', false, 'error', '請勿重複打卡,請稍候');
  end if;
  -- 上次是「上班」且未超過 12 小時 → 這次是下班;超過 12 小時視為漏打,這次當新的上班
  new_kind := case when found and last_p.kind = 'in' and v_ts - last_p.punched_at <= interval '12 hours'
                   then 'out' else 'in' end;
  v_missed := found and last_p.kind = 'in' and new_kind = 'in';

  begin h := current_setting('request.headers', true)::json; exception when others then h := null; end;
  v_ip := nullif(trim(coalesce(split_part(h->>'x-forwarded-for', ',', 1), h->>'cf-connecting-ip', '')), '');

  insert into public.punches (worker_id, kind, punched_at, ip) values (w.id, new_kind, v_ts, v_ip);
  return json_build_object('ok', true, 'kind', new_kind, 'name', w.name, 'at', v_ts, 'missed_previous', v_missed);
end $$;

grant execute on function public.list_workers() to anon, authenticated;
grant execute on function public.punch(bigint, text) to anon, authenticated;

-- ========== 後台用的函式(內部會檢查管理員) ==========
create or replace function public.admin_add_worker(p_name text, p_pin text) returns bigint
language plpgsql security definer set search_path = public, extensions as $$
declare v_id bigint;
begin
  if not public.is_admin() then raise exception '無權限' using errcode = '42501'; end if;
  if p_pin !~ '^[0-9]{4,8}$' then raise exception 'PIN 需為 4~8 位數字'; end if;
  insert into public.workers (name, pin_hash) values (trim(p_name), crypt(p_pin, gen_salt('bf')))
    returning id into v_id;
  return v_id;
end $$;

create or replace function public.admin_set_pin(p_worker_id bigint, p_pin text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_admin() then raise exception '無權限' using errcode = '42501'; end if;
  if p_pin !~ '^[0-9]{4,8}$' then raise exception 'PIN 需為 4~8 位數字'; end if;
  update public.workers set pin_hash = crypt(p_pin, gen_salt('bf')),
    failed_attempts = 0, locked_until = null where id = p_worker_id;
end $$;

grant execute on function public.is_admin() to authenticated;
grant execute on function public.admin_add_worker(text, text) to authenticated;
grant execute on function public.admin_set_pin(bigint, text) to authenticated;

-- ========== 設定管理員(把信箱換成你在 Supabase Auth 建立的帳號) ==========
-- insert into public.admins (user_id) select id from auth.users where email = '你的信箱';

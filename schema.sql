-- 在 Supabase Dashboard > SQL Editor 貼上執行
create table if not exists public.messages (
  id bigint generated always as identity primary key,
  name text not null check (char_length(name) between 1 and 30),
  content text not null check (char_length(content) between 1 and 500),
  created_at timestamptz not null default now()
);

-- 由伺服器端記錄留言者 IP(從 PostgREST 請求標頭取得,前端無法偽造)
alter table public.messages add column if not exists ip text;

create or replace function public.set_message_ip() returns trigger
language plpgsql security definer set search_path = public as $$
declare h json;
begin
  begin h := current_setting('request.headers', true)::json; exception when others then h := null; end;
  new.ip := nullif(trim(coalesce(split_part(h->>'x-forwarded-for', ',', 1), h->>'cf-connecting-ip', '')), '');
  return new;
end $$;

drop trigger if exists messages_set_ip on public.messages;
create trigger messages_set_ip before insert on public.messages
  for each row execute function public.set_message_ip();

grant usage on schema public to anon;
grant select, insert on public.messages to anon;

alter table public.messages enable row level security;

-- 任何人可讀取、可新增;不開放修改與刪除
create policy "messages_select" on public.messages for select to anon using (true);
create policy "messages_insert" on public.messages for insert to anon with check (true);

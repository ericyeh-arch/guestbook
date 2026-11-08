-- 在 Supabase Dashboard > SQL Editor 貼上執行
create table if not exists public.messages (
  id bigint generated always as identity primary key,
  name text not null check (char_length(name) between 1 and 30),
  content text not null check (char_length(content) between 1 and 500),
  created_at timestamptz not null default now()
);

grant usage on schema public to anon;
grant select, insert on public.messages to anon;

alter table public.messages enable row level security;

-- 任何人可讀取、可新增;不開放修改與刪除
create policy "messages_select" on public.messages for select to anon using (true);
create policy "messages_insert" on public.messages for insert to anon with check (true);

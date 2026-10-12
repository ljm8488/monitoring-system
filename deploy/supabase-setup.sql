-- 감염관리 Smart Monitoring System · Supabase 초기 설정
-- Supabase 대시보드 → SQL Editor → New query → 전체 붙여넣기 → Run
-- 아래 맨 끝 두 줄의 '기관코드'와 '접속비밀키'를 원하는 값으로 바꾼 뒤 실행하십시오.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.sms_site (
  site        text primary key,
  secret_hash text not null
);

create table if not exists public.sms_kv (
  site       text not null references public.sms_site(site) on delete cascade,
  k          text not null,
  v          jsonb,
  updated_at timestamptz not null default now(),
  updated_by text,
  primary key (site, k)
);

create table if not exists public.sms_audit (
  id         bigserial primary key,
  site       text not null,
  k          text not null,
  updated_by text,
  at         timestamptz not null default now()
);

-- 테이블 직접 접근 차단 (정책 없음 = anon/authenticated 모두 거부)
alter table public.sms_site  enable row level security;
alter table public.sms_kv    enable row level security;
alter table public.sms_audit enable row level security;
revoke all on public.sms_site, public.sms_kv, public.sms_audit from anon, authenticated;

create or replace function public.sms_check(p_site text, p_secret text)
returns boolean language sql security definer set search_path = public, extensions as $$
  select exists (select 1 from sms_site where site = p_site and secret_hash = extensions.crypt(p_secret, secret_hash));
$$;

create or replace function public.sms_get(p_site text, p_secret text)
returns table (k text, v jsonb, updated_at timestamptz, updated_by text)
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not sms_check(p_site, p_secret) then raise exception '기관 코드 또는 접속 비밀키가 올바르지 않습니다.'; end if;
  return query select kv.k, kv.v, kv.updated_at, kv.updated_by from sms_kv kv where kv.site = p_site;
end $$;

create or replace function public.sms_put(p_site text, p_secret text, p_k text, p_v jsonb, p_by text default '')
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not sms_check(p_site, p_secret) then raise exception '기관 코드 또는 접속 비밀키가 올바르지 않습니다.'; end if;
  insert into sms_kv(site, k, v, updated_at, updated_by) values (p_site, p_k, p_v, now(), p_by)
  on conflict (site, k) do update set v = excluded.v, updated_at = now(), updated_by = excluded.updated_by;
  insert into sms_audit(site, k, updated_by) values (p_site, p_k, p_by);
end $$;

revoke all on function public.sms_check(text, text) from public, anon, authenticated;
grant execute on function public.sms_get(text, text) to anon;
grant execute on function public.sms_put(text, text, text, jsonb, text) to anon;

-- ▼ 기관 등록: '기관코드', '접속비밀키'를 바꿔서 실행 (비밀키는 16자 이상 권장)
insert into public.sms_site(site, secret_hash)
values ('기관코드', extensions.crypt('접속비밀키', extensions.gen_salt('bf')))
on conflict (site) do update set secret_hash = excluded.secret_hash;

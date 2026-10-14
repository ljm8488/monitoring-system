-- 감염관리 Smart Monitoring System · Supabase 클라우드 동기화 설정
-- Supabase 대시보드 → SQL Editor → New query → 전체 붙여넣기 → Run
--
-- ■ 실행 방법
--   · 처음 설치 : 맨 아래 [2. 기관 등록]의 '기관코드'와 '접속비밀키'를 원하는 값으로 바꾼 뒤 전체 실행
--   · 이미 사용 중인 DB : 그대로 전체 실행해도 안전합니다.
--       - 테이블·데이터는 지우지 않습니다 (create if not exists / create or replace 만 사용).
--       - 기관 등록은 이미 있는 기관이면 건너뜁니다 (비밀키가 바뀌지 않음).
--       - 비밀키를 바꾸려면 맨 아래 [3. 비밀키 변경]의 주석을 풀어 실행하십시오.
--
-- ■ 동기화 구조
--   앱은 데이터를 "항목 이름(k) + 값(v, JSON)" 형태로 sms_kv 테이블에 저장합니다.
--   새 동기화 항목이 추가되어도 DB 구조 변경 없이 그대로 저장됩니다.
--   앱이 호출하는 함수는 sms_get(조회), sms_put(저장) 두 가지뿐입니다.
--
-- ■ 현재 동기화 항목 (앱의 SYNC_KEYS · 2026-10-14 기준)
--   [사용자·권한]
--     users        직원 계정·권한·알림 메일        permLog     권한 변경 이력
--     tabOrders    사용자별 좌측 메뉴 순서 (기관|사번 별로 저장)
--   [기준정보]
--     orgs         소속 기관 목록                  depts       부서 목록
--     ranks        직책 목록                       customItems 직접 추가한 검사항목
--   [환자·검사]
--     manual       수동 반영 환자                  regs        환자·검사항목 등록 내역
--     results      등록된 검사 결과                extraHistory 환자별 추가 검사 이력 (CPE 추가검사 포함)
--     extraReport  결과지 캡처로 확정된 결과지     queueDone   결과 등록 보류 목록
--     dropped      관리 대상 제외 환자             done        처리 완료 알림
--     cleared      해제 판정 환자                  sampleOff   샘플 데이터 정리 시각
--   [업무]
--     handovers    인수인계                        priv / privLog  개인정보 보호 설정·열람 이력
--   [알림 메일]
--     mailLog      메일 발송 로그                  mailSent    발송 완료 알림
--     autoSent     자동 발송 완료 알림             recipients  메일 수신자
--     mailRules    메일 발송 규칙                  mailAuto    자동 발송 사용 여부
--   [연동관리]
--     emrDown      EMR 연동 중단 여부              emrSince    연동 중단 시작 시각
--     emrLog       EMR 연동 상태 변경 이력 (누가·언제 중단/복구)

create extension if not exists pgcrypto with schema extensions;

-- ═══ 1. 테이블 · 함수 (다시 실행해도 안전) ═══════════════════════════════

-- 기관(사이트)별 접속 비밀키 (bcrypt 해시로만 저장)
create table if not exists public.sms_site (
  site        text primary key,
  secret_hash text not null
);

-- 동기화 데이터: 기관별 "항목 이름 → JSON 값"
create table if not exists public.sms_kv (
  site       text not null references public.sms_site(site) on delete cascade,
  k          text not null,
  v          jsonb,
  updated_at timestamptz not null default now(),
  updated_by text,
  primary key (site, k)
);

-- 저장 이력: 언제 누가 어떤 항목을 저장했는지 (값은 남기지 않음)
create table if not exists public.sms_audit (
  id         bigserial primary key,
  site       text not null,
  k          text not null,
  updated_by text,
  at         timestamptz not null default now()
);
create index if not exists sms_audit_site_at on public.sms_audit (site, at desc);

-- 테이블 직접 접근 차단 (정책 없음 = anon/authenticated 모두 거부, 아래 함수로만 접근)
alter table public.sms_site  enable row level security;
alter table public.sms_kv    enable row level security;
alter table public.sms_audit enable row level security;
revoke all on public.sms_site, public.sms_kv, public.sms_audit from anon, authenticated;

-- 기관 코드 + 비밀키 확인 (내부용)
create or replace function public.sms_check(p_site text, p_secret text)
returns boolean language sql security definer set search_path = public, extensions as $$
  select exists (select 1 from sms_site where site = p_site and secret_hash = extensions.crypt(p_secret, secret_hash));
$$;

-- 조회: 기관의 모든 동기화 항목을 돌려줌 (앱 시작·주기적 갱신 시 호출)
create or replace function public.sms_get(p_site text, p_secret text)
returns table (k text, v jsonb, updated_at timestamptz, updated_by text)
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not sms_check(p_site, p_secret) then raise exception '기관 코드 또는 접속 비밀키가 올바르지 않습니다.'; end if;
  return query select kv.k, kv.v, kv.updated_at, kv.updated_by from sms_kv kv where kv.site = p_site;
end $$;

-- 저장: 항목 하나를 저장(없으면 추가, 있으면 덮어씀)하고 저장 이력을 남김 (변경 시 약 1초 내 호출)
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

-- ═══ 2. 기관 등록 (처음 한 번) ════════════════════════════════════════
-- '기관코드', '접속비밀키'를 바꿔서 실행 (비밀키는 16자 이상 권장)
-- 이미 등록된 기관이면 아무것도 바꾸지 않습니다.
insert into public.sms_site(site, secret_hash)
values ('기관코드', extensions.crypt('접속비밀키', extensions.gen_salt('bf')))
on conflict (site) do nothing;

-- ═══ 3. 비밀키 변경 (필요할 때만 주석 해제) ══════════════════════════
-- 변경 후에는 모든 PC에서 새 비밀키로 다시 연결해야 합니다.
-- update public.sms_site
--    set secret_hash = extensions.crypt('새접속비밀키', extensions.gen_salt('bf'))
--  where site = '기관코드';

-- ═══ 참고: 저장 현황 확인 (SQL Editor에서 조회용) ═════════════════════
-- select k, updated_at, updated_by from public.sms_kv where site = '기관코드' order by updated_at desc;
-- select * from public.sms_audit where site = '기관코드' order by at desc limit 50;

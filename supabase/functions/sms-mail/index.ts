// [감염관리 Smart Monitoring System] 알림 메일 발송 서버 (Supabase Edge Function · Deno)
//
// 앱이 보낸 알림 메일을 Gmail(SMTP)로 실제 발송한다.
//  · 기관 코드 + 접속 비밀키를 sms_get 으로 확인한 뒤에만 발송한다.
//  · 받는 사람은 그 기관의 직원 계정(users)에 등록된 이메일로만 제한한다 (다른 주소는 무시).
//  · 발송 계정은 함수 비밀값 GMAIL_USER / GMAIL_APP_PASSWORD (Gmail 앱 비밀번호) 를 사용한다.
//
// 배포 방법은 deploy/메일발송_설정안내.txt 참고. 앱이 자체적으로 비밀키를 확인하므로 JWT 검사는 끕니다(--no-verify-jwt).

import nodemailer from 'npm:nodemailer@6.9.14';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

type Mail = { to?: string[]; subject?: string; text?: string };

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  if (req.method !== 'POST') return json({ error: 'POST만 지원합니다.' }, 405);
  try {
    const { site, secret, mails, test } = await req.json();
    if (!site || !secret) return json({ error: '기관 코드와 접속 비밀키가 필요합니다.' }, 400);

    // 1) 기관 코드 + 비밀키 확인 (틀리면 sms_get 이 오류) · 직원 계정 목록도 함께 받음
    const url = Deno.env.get('SUPABASE_URL')!, anon = Deno.env.get('SUPABASE_ANON_KEY')!;
    const r = await fetch(url + '/rest/v1/rpc/sms_get', {
      method: 'POST',
      headers: { apikey: anon, Authorization: 'Bearer ' + anon, 'Content-Type': 'application/json' },
      body: JSON.stringify({ p_site: site, p_secret: secret }),
    });
    if (!r.ok) return json({ error: '기관 코드 또는 접속 비밀키가 올바르지 않습니다.' }, 401);
    const rows: { k: string; v: unknown }[] = await r.json();
    const users = (rows.find((x) => x.k === 'users')?.v as { email?: string }[]) || [];
    const allowed = new Set(users.map((u) => String(u.email || '').trim().toLowerCase()).filter(Boolean));

    // 2) Gmail 발송 계정
    const user = Deno.env.get('GMAIL_USER'), pass = Deno.env.get('GMAIL_APP_PASSWORD');
    if (!user || !pass) return json({ error: '메일 서버에 GMAIL_USER / GMAIL_APP_PASSWORD 비밀값이 설정되지 않았습니다.' }, 500);
    const tr = nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user, pass } });
    if (test === 'verify') { await tr.verify(); return json({ ok: true, from: user }); }

    // 3) 발송 (한 번에 최대 50통)
    const list: Mail[] = Array.isArray(mails) ? mails.slice(0, 50) : [];
    const results = [];
    for (const m of list) {
      const to = (m.to || []).map((x) => String(x).trim().toLowerCase()).filter((x) => allowed.has(x));
      if (!to.length) { results.push({ ok: false, reason: '등록된 직원 이메일이 아닌 수신자' }); continue; }
      try {
        await tr.sendMail({ from: `감염관리 알림 <${user}>`, to: to.join(','),
          subject: String(m.subject || '[감염관리 알림]').slice(0, 200), text: String(m.text || '').slice(0, 5000) });
        results.push({ ok: true, to: to.length });
      } catch (e) {
        results.push({ ok: false, reason: String((e as Error)?.message || e).slice(0, 160) });
      }
    }
    return json({ results });
  } catch (e) {
    return json({ error: String((e as Error)?.message || e).slice(0, 200) }, 500);
  }
});

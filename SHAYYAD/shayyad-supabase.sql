-- =====================================================================
-- شَيَّاد — إعداد قاعدة البيانات في Supabase
-- الصق هذا الملف كاملًا في: SQL Editor ← New query ← Run
-- آمن للتشغيل أكثر من مرة.
-- =====================================================================

-- 1) الملفات الشخصية (مرتبطة بحسابات Supabase Auth)
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text not null default '',
  phone       text,
  city        text,
  role        text not null default 'owner' check (role in ('owner','pro')),
  service     text,
  company     text,
  cr          text,
  bio         text,
  notif       jsonb default '{"email":true,"sms":true,"whatsapp":false,"weekly":true}'::jsonb,
  pro_data    jsonb,
  created_at  timestamptz not null default now()
);

-- إنشاء الملف الشخصي تلقائيًا عند تسجيل مستخدم جديد
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name, phone, city, role, service)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
    new.raw_user_meta_data->>'phone',
    new.raw_user_meta_data->>'city',
    coalesce(new.raw_user_meta_data->>'role', 'owner'),
    new.raw_user_meta_data->>'service'
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 2) المشاريع (كل مشروع محفوظ كـ JSON: المراحل، الفريق، الرسائل، التراخيص، الجدوى، بيانات الملفات)
create table if not exists public.projects (
  id          text primary key,
  owner       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  data        jsonb not null,
  updated_at  timestamptz not null default now()
);
create index if not exists projects_owner_idx on public.projects(owner, updated_at desc);

-- 3) تقييمات المختصين (عامة للقراءة، وكل مستخدم يكتب تقييماته فقط)
create table if not exists public.reviews (
  id             bigint generated always as identity primary key,
  specialist_id  text not null,
  project_id     text,
  phase_id       text,
  user_id        uuid not null default auth.uid() references auth.users(id) on delete cascade,
  rating         int  not null check (rating between 1 and 5),
  comment        text check (char_length(comment) <= 1000),
  created_at     timestamptz not null default now(),
  unique (user_id, phase_id)
);
create index if not exists reviews_sp_idx on public.reviews(specialist_id);

-- 4) تذاكر الدعم (أي زائر يرسل، ولا أحد يقرأ من الموقع — تقرأها أنت من لوحة Supabase)
create table if not exists public.support_tickets (
  id          bigint generated always as identity primary key,
  user_id     uuid references auth.users(id) on delete set null,
  name        text,
  email       text,
  kind        text,
  message     text not null check (char_length(message) between 10 and 4000),
  created_at  timestamptz not null default now()
);

-- 5) طلبات عروض الأسعار
create table if not exists public.quote_requests (
  id             bigint generated always as identity primary key,
  user_id        uuid not null default auth.uid() references auth.users(id) on delete cascade,
  specialist_id  text not null,
  details        text not null check (char_length(details) <= 4000),
  budget         numeric,
  city           text,
  created_at     timestamptz not null default now()
);

-- =====================================================================
-- قواعد الصلاحيات (Row Level Security) — هي اللي تحمي البيانات
-- =====================================================================
alter table public.profiles        enable row level security;
alter table public.projects        enable row level security;
alter table public.reviews         enable row level security;
alter table public.support_tickets enable row level security;
alter table public.quote_requests  enable row level security;

drop policy if exists "profiles: read own"   on public.profiles;
drop policy if exists "profiles: insert own" on public.profiles;
drop policy if exists "profiles: update own" on public.profiles;
create policy "profiles: read own"   on public.profiles for select to authenticated using (id = auth.uid());
create policy "profiles: insert own" on public.profiles for insert to authenticated with check (id = auth.uid());
create policy "profiles: update own" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists "projects: owner all" on public.projects;
create policy "projects: owner all" on public.projects for all to authenticated
  using (owner = auth.uid()) with check (owner = auth.uid());

drop policy if exists "reviews: public read" on public.reviews;
drop policy if exists "reviews: insert own"  on public.reviews;
create policy "reviews: public read" on public.reviews for select to anon, authenticated using (true);
create policy "reviews: insert own"  on public.reviews for insert to authenticated with check (user_id = auth.uid());

drop policy if exists "tickets: anyone can send" on public.support_tickets;
create policy "tickets: anyone can send" on public.support_tickets for insert to anon, authenticated
  with check (user_id is null or user_id = auth.uid());

drop policy if exists "quotes: insert own" on public.quote_requests;
drop policy if exists "quotes: read own"   on public.quote_requests;
create policy "quotes: insert own" on public.quote_requests for insert to authenticated with check (user_id = auth.uid());
create policy "quotes: read own"   on public.quote_requests for select to authenticated using (user_id = auth.uid());

-- =====================================================================
-- حذف الحساب من داخل الموقع (الموقع يحذف الملفات أولًا، وهذي الدالة تحذف المستخدم وكل بياناته)
-- =====================================================================
create or replace function public.delete_my_account()
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  delete from auth.users where id = auth.uid();
end $$;
revoke all on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;

-- =====================================================================
-- تخزين الملفات: مجلد خاص لكل مستخدم داخل bucket اسمه deliverables
-- =====================================================================
insert into storage.buckets (id, name, public, file_size_limit)
values ('deliverables', 'deliverables', false, 26214400)
on conflict (id) do nothing;

drop policy if exists "deliverables: read own"   on storage.objects;
drop policy if exists "deliverables: upload own" on storage.objects;
drop policy if exists "deliverables: delete own" on storage.objects;
create policy "deliverables: read own" on storage.objects for select to authenticated
  using (bucket_id = 'deliverables' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "deliverables: upload own" on storage.objects for insert to authenticated
  with check (bucket_id = 'deliverables' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "deliverables: delete own" on storage.objects for delete to authenticated
  using (bucket_id = 'deliverables' and (storage.foldername(name))[1] = auth.uid()::text);

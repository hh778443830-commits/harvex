const enc = new TextEncoder();
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8', ...headers}});
const hex = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const randomId = () => crypto.randomUUID();
async function hashPassword(password, saltHex) {
  const salt = saltHex ? Uint8Array.from(saltHex.match(/.{2}/g), x=>parseInt(x,16)) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations:210000, hash:'SHA-256'}, key, 256);
  return `${hex(salt)}:${hex(bits)}`;
}
async function digest(value) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(value))); }
function cookie(name, value, maxAge) { return `${name}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`; }
async function currentUser(request, env) {
  const raw = request.headers.get('Cookie')?.match(/harvex_session=([^;]+)/)?.[1];
  if (!raw) return null;
  const row = await env.DB.prepare('SELECT users.id, users.username, users.display_name, users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?').bind(await digest(raw), Math.floor(Date.now()/1000)).first();
  return row || null;
}
async function handle(request, env) {
  const url = new URL(request.url);
  if (url.pathname === '/api/health') return json({ok:true, app:'HARVEX', database:!!env.DB});
  if (url.pathname === '/api/setup/first-engineer' && request.method === 'POST') {
    const body = await request.json().catch(()=>({}));
    if (!env.BOOTSTRAP_KEY || body.bootstrapKey !== env.BOOTSTRAP_KEY) return json({error:'مفتاح التهيئة غير صحيح'}, 403);
    if (!body.username || !body.displayName || !body.password || body.password.length < 12) return json({error:'أدخل البيانات وكلمة مرور لا تقل عن 12 حرفاً'}, 400);
    const exists = await env.DB.prepare("SELECT id FROM users WHERE role='engineer' LIMIT 1").first();
    if (exists) return json({error:'تم إنشاء حساب المهندس مسبقاً'}, 409);
    try {
      await env.DB.prepare('INSERT INTO users(id,username,display_name,password_hash,role) VALUES(?,?,?,?,?)').bind(randomId(), body.username.trim(), body.displayName.trim(), await hashPassword(body.password), 'engineer').run();
      return json({ok:true, message:'تم إنشاء حساب المهندس. سجّل الدخول الآن.'}, 201);
    } catch { return json({error:'اسم المستخدم مستخدم أو تعذر إنشاء الحساب'}, 409); }
  }
  if (url.pathname === '/api/login' && request.method === 'POST') {
    const body = await request.json().catch(()=>({}));
    const user = await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(body.username || '').first();
    if (!user || !body.password) return json({error:'اسم المستخدم أو كلمة المرور غير صحيحة'}, 401);
    const [salt, expected] = user.password_hash.split(':');
    const actual = (await hashPassword(body.password, salt)).split(':')[1];
    if (actual !== expected) return json({error:'اسم المستخدم أو كلمة المرور غير صحيحة'}, 401);
    const token = hex(crypto.getRandomValues(new Uint8Array(32)));
    await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await digest(token), user.id, Math.floor(Date.now()/1000)+604800).run();
    return json({ok:true,user:{username:user.username,displayName:user.display_name,role:user.role}},200,{'set-cookie':cookie('harvex_session',token,604800)});
  }
  if (url.pathname === '/api/logout' && request.method === 'POST') {
    const raw = request.headers.get('Cookie')?.match(/harvex_session=([^;]+)/)?.[1];
    if (raw) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(raw)).run();
    return json({ok:true},200,{'set-cookie':cookie('harvex_session','',0)});
  }
  const user = await currentUser(request, env);
  if (url.pathname === '/api/me') return user ? json({user}) : json({user:null},401);
  if (!user) return json({error:'يلزم تسجيل الدخول'},401);
  if (user.role !== 'engineer') return json({error:'ليست لديك الصلاحية'},403);
  if (url.pathname === '/api/customers' && request.method === 'GET') {
    const {results} = await env.DB.prepare('SELECT * FROM customers ORDER BY created_at DESC').all();
    return json({customers:results});
  }
  if (url.pathname === '/api/customers' && request.method === 'POST') {
    const body = await request.json().catch(()=>({}));
    if (!body.name?.trim()) return json({error:'اسم العميل مطلوب'},400);
    const id = randomId();
    await env.DB.prepare('INSERT INTO customers(id,name,phone,notes) VALUES(?,?,?,?)').bind(id,body.name.trim(),body.phone||null,body.notes||null).run();
    return json({ok:true,id},201);
  }
  if (url.pathname === '/api/sites' && request.method === 'POST') {
    const body = await request.json().catch(()=>({}));
    if (!body.customerId || !body.name?.trim()) return json({error:'اختر العميل واكتب اسم الموقع'},400);
    const id = randomId();
    await env.DB.prepare('INSERT INTO sites(id,customer_id,name,address,recorder_type) VALUES(?,?,?,?,?)').bind(id,body.customerId,body.name.trim(),body.address||null,body.recorderType||null).run();
    return json({ok:true,id},201);
  }
  return json({error:'المسار غير موجود'},404);
}
export default { fetch(request, env) { return handle(request, env).catch(err => { console.error(err); return json({error:'حدث خطأ داخلي؛ تحقق من إعداد قاعدة البيانات'},500); }); } };

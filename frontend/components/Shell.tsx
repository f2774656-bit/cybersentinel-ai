"use client";
import Link from "next/link";
import {usePathname,useRouter} from "next/navigation";
import {useEffect,useState} from "react";
import {api,clearAuth,User} from "../lib/api";
import {dictionary,Lang} from "../lib/i18n";

const nav=[
  ['/dashboard','dashboard'],['/targets','targets'],['/scans','scans'],['/findings','findings'],
  ['/cloudflare','cloudflare'],['/ai-analyst','ai'],['/reports','reports'],['/settings','settings']
] as const;

export default function Shell({children}:{children:React.ReactNode}){
  const path=usePathname(); const router=useRouter();
  const [u,setU]=useState<User|null>(null); const [fa,setFa]=useState(false); const [online,setOnline]=useState(true);
  const lang:Lang=fa?'fa':'en'; const t=dictionary[lang];
  useEffect(()=>{
    api.me().then(setU).catch(()=>router.push('/login'));
    const sync=()=>setOnline(navigator.onLine); sync();
    window.addEventListener('online',sync); window.addEventListener('offline',sync);
    return()=>{window.removeEventListener('online',sync);window.removeEventListener('offline',sync)};
  },[router]);
  useEffect(()=>{document.documentElement.dir=fa?'rtl':'ltr';document.documentElement.lang=fa?'fa':'en'},[fa]);
  if(!u)return <div className="min-h-screen grid place-items-center"><div className="glow">INITIALIZING CYBERSENTINEL…</div></div>;
  const mobilePath=path.startsWith('/admin')?'/admin':(nav.find(([h])=>path.startsWith(h))?.[0]||'/dashboard');
  return <div className="min-h-screen flex">
    <aside className="hidden lg:block w-64 p-4 border-r border-[#17352a] bg-black/20">
      <div className="text-xl font-black glow tracking-wider mb-1">CYBERSENTINEL AI</div>
      <div className="text-[11px] muted mb-6">AUTHORIZED SECURITY OPERATIONS</div>
      <nav className="space-y-1">
        {nav.map(([href,key])=><Link key={href} href={href} className={`block rounded-lg px-3 py-2 text-sm ${path.startsWith(href)?'bg-[#0d2018] text-[#00ff88] border border-[#245541]':'text-[#9bb7aa] hover:bg-[#0c1611]'}`}>{t[key]}</Link>)}
        {u.role==='ADMIN'&&<><div className="muted text-[10px] pt-5 pb-2">{t.admin}</div><Link href="/admin" className="block px-3 py-2 text-sm">Overview</Link><Link href="/admin/users" className="block px-3 py-2 text-sm">{t.users}</Link><Link href="/admin/audit-logs" className="block px-3 py-2 text-sm">{t.audit}</Link><Link href="/admin/system" className="block px-3 py-2 text-sm">{t.system}</Link></>}
      </nav>
    </aside>
    <main className="flex-1 min-w-0">
      <header className="sticky top-0 z-20 backdrop-blur bg-black/40 border-b border-[#17352a] px-4 lg:px-8 py-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0"><div className="lg:hidden glow font-bold whitespace-nowrap">CYBERSENTINEL AI</div><select className="lg:hidden !w-auto !py-2" value={mobilePath} onChange={e=>router.push(e.target.value)}><option value="/dashboard">{t.dashboard}</option><option value="/targets">{t.targets}</option><option value="/scans">{t.scans}</option><option value="/findings">{t.findings}</option><option value="/cloudflare">{t.cloudflare}</option><option value="/ai-analyst">{t.ai}</option><option value="/reports">{t.reports}</option><option value="/settings">{t.settings}</option>{u.role==='ADMIN'&&<option value="/admin">{t.admin}</option>}</select></div>
        <div className="flex items-center gap-3"><div className="text-sm muted">{u.name} · <span className="text-[#00ff88]">{u.role}</span></div>{!online&&<span className="text-xs text-red-300 border border-red-900/60 px-2 py-1 rounded">OFFLINE</span>}</div>
        <div className="flex gap-2"><button className="btn" onClick={()=>setFa(x=>!x)}>{t.rtl}</button><button className="btn" onClick={()=>{clearAuth();router.push('/login')}}>{t.logout}</button></div>
      </header>
      <div className="p-4 lg:p-8 max-w-[1600px] mx-auto">{children}</div>
    </main>
  </div>;
}

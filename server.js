require("dotenv").config();
const express = require("express");
const crypto = require("node:crypto");
const app = express();
app.disable("x-powered-by");
const {DISCORD_CLIENT_ID: clientId, DISCORD_CLIENT_SECRET: clientSecret, PUBLIC_URL: publicUrl, SESSION_SECRET: secret} = process.env;
if (![clientId,clientSecret,publicUrl,secret].every(Boolean) || secret.length < 32) {
 throw Error("Set DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, PUBLIC_URL and a SESSION_SECRET of at least 32 characters");
}
const origin = new URL(publicUrl).origin;
const redirectUri = origin + "/callback";
const api = "https://discord.com/api/v10";
const sign = value => crypto.createHmac("sha256",secret).update(value).digest("hex");
const esc = value => String(value).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function page(message){return `<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Rollen-Verifizierung</title><body style="font:18px system-ui;max-width:650px;margin:60px auto;padding:20px;background:#202127;color:white"><h1>Discord Rollen-Verifizierung</h1><p>${esc(message)}</p><a style="color:#9aaaff" href="/login">Mit Discord verbinden</a></body></html>`;}
app.get("/",(_req,res)=>res.type("html").send(page("Verbinde deinen Discord-Account, um deine berechtigten Rollen zu prüfen.")));
app.get("/health",(_req,res)=>res.json({ok:true}));
app.get("/login",(_req,res)=>{
 const nonce=crypto.randomBytes(24).toString("hex");
 const stamp=Date.now().toString();
 const state=`${nonce}.${stamp}.${sign(nonce+"."+stamp)}`;
 res.cookie("oauth_state",state,{httpOnly:true,secure:true,sameSite:"lax",maxAge:600000,path:"/"});
 const q=new URLSearchParams({client_id:clientId,redirect_uri:redirectUri,response_type:"code",scope:"identify role_connections.write",state,prompt:"consent"});
 res.redirect("https://discord.com/oauth2/authorize?"+q);
});
function cookie(req,key){const c=(req.headers.cookie||"").split(";").map(s=>s.trim()).find(s=>s.startsWith(key+"="));return c?decodeURIComponent(c.slice(key.length+1)):"";}
// Process-local cooldown; a restart cannot clear a restriction enforced by Discord.
let tokenCooldownUntil = 0;
const consumedCodes = new Map();
function pruneCodes() {
 const now=Date.now();
 for(const [key,expires] of consumedCodes) if(expires<=now) consumedCodes.delete(key);
}
function waitMessage() {
 const minutes=Math.ceil(Math.max(0,tokenCooldownUntil-Date.now())/60000);
 return "Discord begrenzt derzeit die Anmeldung. Bitte versuche es in etwa "+minutes+" Minute(n) erneut.";
}
function retryDelayMs(value) {
 if(!value) return 60000;
 const seconds=Number(value);
 if(Number.isFinite(seconds) && seconds>=0) return Math.min(Math.ceil(seconds*1000),86400000);
 const timestamp=Date.parse(value);
 return Number.isFinite(timestamp) ? Math.min(Math.max(0,timestamp-Date.now()),86400000) : 60000;
}
function eligible(key,id){const allowed=(process.env[key+"_IDS"]||"").split(",").map(x=>x.trim()).filter(Boolean);return allowed.includes(id)?1:0;}
app.get("/callback",async(req,res)=>{
 try{
  const state=String(req.query.state||"");
  const stored=cookie(req,"oauth_state");
  res.clearCookie("oauth_state",{path:"/"});
  const parts=state.split(".");
  if(!stored || state!==stored || parts.length!==3 || !/^\d+$/.test(parts[1]) || Math.abs(Date.now()-Number(parts[1]))>600000 || !crypto.timingSafeEqual(Buffer.from(parts[2],"hex"),Buffer.from(sign(parts[0]+"."+parts[1]),"hex"))) return res.status(403).send(page("Ungültige oder abgelaufene Anmeldung."));
  if(typeof req.query.code!=="string") return res.status(400).send(page("Anmeldung abgebrochen."));
  if(Date.now()<tokenCooldownUntil) return res.status(429).type("html").send(page(waitMessage()));
  pruneCodes();
  const codeKey=crypto.createHash("sha256").update(req.query.code).digest("hex");
  if(consumedCodes.has(codeKey)) return res.status(400).type("html").send(page("Dieser Anmeldelink wurde bereits verwendet. Bitte starte eine neue Anmeldung."));
  consumedCodes.set(codeKey,Date.now()+600000);
  const tokenRes=await fetch("https://discord.com/api/oauth2/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({client_id:clientId,client_secret:clientSecret,grant_type:"authorization_code",code:req.query.code,redirect_uri:redirectUri})});
  if(!tokenRes.ok){
    const retryAfter=tokenRes.headers.get("retry-after");
    if(tokenRes.status===429) tokenCooldownUntil=Math.max(tokenCooldownUntil,Date.now()+retryDelayMs(retryAfter));
    const rateResetAfter=tokenRes.headers.get("x-ratelimit-reset-after");
    const rateScope=tokenRes.headers.get("x-ratelimit-scope");
    const requestId=tokenRes.headers.get("x-discord-request-id") || tokenRes.headers.get("cf-ray");
    // Do not log response bodies: OAuth responses may contain sensitive values.
    console.error("Discord OAuth token exchange diagnostic", {
      status:tokenRes.status,
      statusText:tokenRes.statusText,
      retryAfter:retryAfter || "not provided",
      rateLimitResetAfter:rateResetAfter || "not provided",
      rateLimitScope:rateScope || "not provided",
      requestId:requestId || "not provided"
    });
    if(tokenRes.status===429) return res.status(429).type("html").send(page(waitMessage()));
    throw Error("Token exchange failed: "+tokenRes.status);
  }
  const {access_token:accessToken}=await tokenRes.json();
  const auth={Authorization:"Bearer "+accessToken};
  const userRes=await fetch(api+"/users/@me",{headers:auth});
  if(!userRes.ok)throw Error("Could not read Discord user");
  const user=await userRes.json();
  const metadata={founder:eligible("FOUNDER",user.id),staff:eligible("STAFF",user.id),admin:eligible("ADMIN",user.id),moderator:eligible("MODERATOR",user.id),helper:eligible("HELPER",user.id)};
  const update=await fetch(api+"/users/@me/applications/"+clientId+"/role-connection",{method:"PUT",headers:{...auth,"Content-Type":"application/json"},body:JSON.stringify({platform_name:"Eigener Rollen-Bot",platform_username:user.username,metadata})});
  if(!update.ok)throw Error("Role connection update failed: "+update.status+" "+(await update.text()).slice(0,300));
  res.type("html").send(page("Verifizierung erfolgreich. Du kannst zurück zu Discord wechseln und deine verknüpften Rollen auswählen."));
 }catch(err){console.error(err);res.status(500).type("html").send(page("Verifizierung fehlgeschlagen. Prüfe die Server-Logs und die Discord-Konfiguration."));}
});
// Register Discord's linked-role criteria when a bot token is configured.
// The web service must stay available even if Discord's API is temporarily unavailable.
const {registerMetadata} = require("./register");
if (process.env.DISCORD_BOT_TOKEN) {
 registerMetadata().catch(error => console.error("Linked Roles setup:", error.message));
} else {
 console.warn("Linked Roles metadata not registered: set DISCORD_BOT_TOKEN in Render environment variables.");
}
app.listen(process.env.PORT||3000,"0.0.0.0",()=>console.log("Web server ready"));

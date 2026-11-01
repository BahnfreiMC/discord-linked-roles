require("dotenv").config();
const { DISCORD_CLIENT_ID: id, DISCORD_BOT_TOKEN: token } = process.env;
if (!id || !token) throw Error("Missing DISCORD_CLIENT_ID or DISCORD_BOT_TOKEN");
const roles = [
  ["founder", "Gründer", "Vom Betreiber als Gründer bestätigt"],
  ["staff", "Mitarbeiter", "Vom Betreiber als Mitarbeiter bestätigt"],
  ["admin", "Admin", "Vom Betreiber als Admin bestätigt"],
  ["moderator", "Moderator", "Vom Betreiber als Moderator bestätigt"],
  ["helper", "Helfer", "Vom Betreiber als Helfer bestätigt"]
].map(([key,name,description])=>({type:7,key,name,description}));
fetch(`https://discord.com/api/v10/applications/${id}/role-connections/metadata`,{
 method:"PUT",headers:{"Authorization":`Bot ${token}`,"Content-Type":"application/json"},body:JSON.stringify(roles)
}).then(async r=>{const body=await r.text();if(!r.ok)throw Error(`${r.status}: ${body}`);console.log(body)})
.catch(e=>{console.error(e);process.exitCode=1});

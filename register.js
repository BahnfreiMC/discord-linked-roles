require("dotenv").config();

// BooleanEqual = 7: only the value "1" satisfies the linked-role requirement.
const roleMetadata = [
  ["founder", "Inhaber", "Als Inhaber durch Koven bestätigt"],
  ["staff", "Mitarbeiter", "Als Mitarbeiter durch Koven bestätigt"],
  ["admin", "Admin", "Als Administrator durch Koven bestätigt"],
  ["moderator", "Moderator", "Als Moderator durch Koven bestätigt"],
  ["helper", "Helfer", "Als Helfer durch Koven bestätigt"]
].map(([key, name, description]) => ({type: 7, key, name, description}));

async function registerMetadata() {
  const id = process.env.DISCORD_CLIENT_ID;
  const token = process.env.DISCORD_BOT_TOKEN;
  if (!id || !token) {
    throw Error("Linked Roles metadata setup requires DISCORD_CLIENT_ID and DISCORD_BOT_TOKEN in Render environment variables");
  }

  const response = await fetch(`https://discord.com/api/v10/applications/${id}/role-connections/metadata`, {
    method: "PUT",
    headers: {
      Authorization: `Bot ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(roleMetadata)
  });
  if (!response.ok) {
    // Never print the bot token, request headers, or untrusted response bodies.
    throw Error(`Linked Roles metadata registration failed (HTTP ${response.status})`);
  }
  console.log("Linked Roles metadata registered:", roleMetadata.map(item => item.key).join(", "));
}

module.exports = {registerMetadata, roleMetadata};

if (require.main === module) {
  registerMetadata().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

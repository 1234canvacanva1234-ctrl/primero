export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const { userAgent, referer, timestamp } = await request.json();

    const ip =
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For") ||
      "Unknown";

    const country = request.cf?.country || "Unknown";
    const city = request.cf?.city || "Unknown";
    const region = request.cf?.region || "Unknown";

    const WEBHOOK_URL = env.DISCORD_WEBHOOK_URL;

    if (!WEBHOOK_URL) {
      return new Response("Configuration error", { status: 500 });
    }

    const embed = {
      embeds: [{
        title: "🔬 SoraSys Visitor",
        color: 0xff3b7c,
        fields: [
          { name: "IP Address", value: `\`${ip}\``, inline: true },
          { name: "Location", value: `${city}, ${country}`, inline: true },
          { name: "Region", value: region, inline: true },
          { name: "User Agent", value: userAgent ?? "Unknown" },
          { name: "Referer", value: referer || "Direct Visit", inline: true },
          { name: "Time", value: new Date(timestamp).toLocaleString(), inline: true }
        ],
        timestamp: new Date().toISOString()
      }]
    };

    await fetch(WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(embed)
    });

    return new Response("OK");
  } catch (e) {
    console.error(e);
    return new Response("Error", { status: 500 });
  }
}

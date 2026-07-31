const { google } = require("googleapis");

const SPREADSHEET_ID = "1-DkgM90zY6p0cZqn8sGTi26H7v0opp2xxBFsDhjv2Lk";
const SHEET_NAME = "Form Responses 1";

const HEADERS = [
  "Timestamp",
  "HC Name",
  "Email",
  "Slack ID",
  "Verified",
  "Project Name",
  "Live URL",
  "Source URL",
  "File Size (KB)",
  "Description",
  "Tier",
  "Phone",
  "Ship Name",
  "Address 1",
  "Address 2",
  "City",
  "State",
  "Country",
  "Postal Code",
];

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const payload = req.body || {};

  try {
    const auth = new google.auth.GoogleAuth({
      credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON),
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });

    const sheets = google.sheets({ version: "v4", auth });

    const row = [
      payload.timestamp || "",
      payload.hc_name || "",
      payload.hc_email || "",
      payload.hc_slack_id || "",
      payload.hc_verified || "",
      payload.project_name || "",
      payload.project_url || "",
      payload.source_url || "",
      payload.file_size_kb || "",
      payload.description || "",
      payload.tier || "",
      payload.phone || "",
      payload.ship_name || "",
      payload.ship_line1 || "",
      payload.ship_line2 || "",
      payload.ship_city || "",
      payload.ship_state || "",
      payload.ship_country || "",
      payload.ship_postal || "",
    ];

    await sheets.spreadsheets.values.append({
      spreadsheetId: SPREADSHEET_ID,
      range: `${SHEET_NAME}!A1`,
      valueInputOption: "USER_ENTERED",
      insertDataOption: "OVERWRITE",
      requestBody: {
        values: [row],
      },
    });

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("Submit error:", err);
    return res.status(500).json({ ok: false, error: err.message });
  }
};

# RecRoom Node Render Server

This is a Node.js port of the uploaded C# server. It is made to run on GitHub + Render with no external npm packages.

## Run locally

```bash
npm install
npm start
```

Open:

```txt
http://localhost:2059/
```

## Deploy on Render

1. Make a new GitHub repo.
2. Upload everything in this folder.
3. On Render, create a new **Web Service** from that repo.
4. Use:

```txt
Build Command: npm install
Start Command: npm start
```

5. Add this environment variable after Render gives you your URL:

```txt
PUBLIC_BASE_URL=https://your-render-app.onrender.com
```

Restart the service after adding it.

## Notes

- This version uses `Data/db.json` for players, rooms, inventions, and saves.
- If `Data/db.json` does not exist, it seeds rooms from `Data/Imports/ImportRooms.json`.
- Render free instances reset their disk sometimes. For long-term saved data, add a Render persistent disk or move the JSON DB to a real database later.
- The old `.db` LiteDB files are not used by this Node version.
- Image resizing from the C# version was simplified. The image server serves existing image files directly.

## Useful test URLs

```txt
/
/api/versioncheck/v4
/api/config/v2
/api/gameconfigs/v1/all
/roomserver/rooms/base
```

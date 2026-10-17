# HeaderHunter Frontend

Professional frontend MVP for HeaderHunter.

## Structure

- `index.html` — page structure and dashboard markup
- `css/styles.css` — visual design and responsive layout
- `js/app.js` — demo data, UI rendering, and backend API integration

## Run

Open the folder in VS Code and use Live Server on `index.html`.

## Backend integration

The current frontend uses demo data:

```js
const USE_MOCK_DATA = true;
```

When the backend is ready, change it to:

```js
const USE_MOCK_DATA = false;
```

The frontend will send:

```http
POST /api/analyze
Content-Type: application/json
```

with:

```json
{
  "url": "https://example.com"
}
```

The backend should return the `score`, `headers`, `findings`, and `ai` fields used by `app.js`.

Keep Ollama/Gemma credentials and server-side configuration out of the browser.

// Local dev server. On Vercel, the files in api/ run as serverless functions and public/ is served as static files.
import express from 'express';
import analyze from './api/analyze.js';
import translateUi from './api/translate-ui.js';

const app = express();
app.use(express.json({ limit: '12mb' }));
app.post('/api/analyze', analyze);
app.post('/api/translate-ui', translateUi);
app.use(express.static('public'));

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Plainly running at http://localhost:${port}` + (process.env.MOCK === '1' ? ' (MOCK mode: no API calls)' : ''));
});

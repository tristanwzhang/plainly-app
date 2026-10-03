# Plainly

Helps older adults and people who read little English understand letters, texts, emails, bills, and voicemails: what it is, whether it looks real or like a scam, and what to do next. Works in 11 languages.

## Run it locally

1. Install Node 20 or newer.
2. `npm install`
3. Copy `.env.example` to `.env` and paste your Anthropic API key (from console.anthropic.com).
4. `npm run dev`, then open http://localhost:3000

No key yet? `npm run mock` runs the whole app with canned answers so you can work on the UI.

## Deploy (free tier is fine for a demo)

1. Push this folder to GitHub.
2. Import the repo in Vercel. `api/` becomes serverless functions and `public/` is served as static files.
3. In the Vercel project settings, add `ANTHROPIC_API_KEY` as an environment variable.

## How it works

- `public/index.html`: the whole front end (one file). Photos are shrunk and converted to JPEG in the browser. Pasted text and the built-in examples have personal details hidden in the browser before anything is sent.
- `api/analyze.js`: builds the prompt and calls Claude with the text or photos. Returns JSON that the page renders.
- `api/translate-ui.js`: translates the interface text into the chosen language (cached per server instance).
- `lib/prompt.js`: the prompt, including the scam signs and the "never tell them to pay or call a number from the message" rule.
- Models are set in `.env` (`CLAUDE_MODEL`, `CLAUDE_FAST_MODEL`). Check the current model names in the Anthropic docs.

## Known gaps (good roadmap slides)

- Photos are not redacted. Next step: run OCR in the browser, hide personal details, send only cleaned text.
- Voicemail works as pasted transcripts only. Real audio needs speech-to-text on the server.
- Rate limiting is a best-effort speed bump. Use a shared store (for example Upstash Redis) before real users.
- The prompt has not been measured for accuracy. Build a set of 30 to 50 labeled real and fake messages and track how often the verdict is right.
- Translations have not been checked by native speakers.
- Add a short terms-of-use and a first-use notice before real users upload anything.

## Privacy notes

The server does not store or log letter content, and responses are sent with `Cache-Control: no-store`. Your model provider's own data-retention terms still apply, so read them before making any promise to users.

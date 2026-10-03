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

- `public/index.html`: the whole front end (one file). Pasted text and the built-in examples have personal details hidden in the browser before anything is sent. Photo input was removed: reading a letter from a photograph needs a model, and this build runs with no API key, so the buttons could only ever return an error. The server still accepts images, so restoring it means putting the buttons back and setting a key.
- `api/analyze.js`: builds the prompt and calls Claude with the text or photos. Returns JSON that the page renders.
- `api/translate-ui.js`: serves the shipped translations in `data/ui-strings.js` for the 10 non-English languages, instantly and without a model. It only calls the model for a language that is missing or incomplete there, and falls back to the static text (English per missing key) when the model is unavailable.
- `lib/prompt.js`: the prompt, including the scam signs and the "never tell them to pay or call a number from the message" rule.
- `data/signal-messages.js`: what each scam signal says, in all 11 languages. The rules emit an id and a few variables, never a finished sentence, so a finding can be worded in any language.
- Models are set in `.env` (`CLAUDE_MODEL`, `CLAUDE_FAST_MODEL`). Check the current model names in the Anthropic docs.

## Offline scam checks (no API key)

`lib/signals.js` scores an item for scam signals using only local rules: no
network, no key, no cost. It runs instantly and keeps working offline.

    npm test                  # 67 tests
    npm run check -- --examples
    npm run check -- "paste a suspicious text here"

It catches what is *structural*: links that do not match the claimed sender,
lookalike domains (`paypa1.com`), punycode, gift-card and crypto demands,
requests for one-time codes, wrong callback numbers for agencies whose real
number we know. Those beat a model at this particular job, because a list
lookup cannot hallucinate that a fake domain looks fine.

**It can only ever raise suspicion.** A message with no signals is not thereby
genuine, so `analyzeSignals` never returns a `"real"` verdict and the UI must
never render "no signs found" as "this is safe". Tone-based rules score 1 on
purpose: real agency mail is genuinely urgent and really does demand money, so
weighting tone highly would flag legitimate letters and teach people to ignore
the warnings that matter.

`api/analyze.js` runs these rules on every text item before it calls the
model, and merges the two. Rules may only make a verdict **more** cautious,
never less, so a model cannot be talked out of a gift-card demand; they escalate
only when something actually fired, so a clean run leaves the model's own
judgment alone. Rule wording is English, so for other languages the model's
reasons are used instead and the rule findings travel as structured `signals`.

Because of this the app degrades instead of failing. With `npm run mock`, with
no key set, or when the model is down or returns junk, you still get a real
verdict from the rules and a `degraded` field saying why. Photo input is the one
case rules cannot help with, since the images are never read as text.

Add local organizations to `data/known-orgs.js`. Leave a `phones` array empty
unless the number is confirmed from the organization's own site — a wrong number
there tells someone a real letter is fake, which is the costlier mistake.

## Known gaps (good roadmap slides)

- Photo input is gone from the UI (see above). If it comes back, it still needs OCR in the browser so personal details are hidden before anything is sent.
- Voicemail works as pasted transcripts only. Real audio needs speech-to-text on the server.
- Rate limiting is a best-effort speed bump. Use a shared store (for example Upstash Redis) before real users.
- Neither the prompt nor the offline rules have been measured for accuracy. Build a set of 30 to 50 labeled real and fake messages and track how often the verdict is right.
- The offline rules read a claimed sender out of prose, so an incidental brand mention is misread as the sender ("Google Play cards" makes it say the message claims to be from Google). Cosmetic today; worth narrowing before real users.
- **The detection itself only understands English.** The explanations are now translated, but the phrase rules that find them are English regexes, so a scam written in Spanish or Vietnamese will not trigger `pay_gift_card`, `ask_password`, `threat` and the rest. The structural rules — domains, lookalikes, punycode, phone numbers — are language-independent and still work. For an audience that reads little English and therefore receives scams in their own language, this is now the largest hole in the product.
- The translations in `data/signal-messages.js` and `data/ui-strings.js` are machine translations and have not been checked by native speakers.
- Redaction runs before the rules see the text, and it can erase a signal: "Dear Valued Customer" becomes "Dear [HIDDEN NAME]", so the generic-greeting rule stops firing. Running the rules in the browser on the original text, before redaction, would fix this. `test/examples.test.js` covers the built-in examples both ways so a regression shows up.
- The interface translations in `data/ui-strings.js` are machine translations and have NOT been checked by native speakers. The audience reads little English, so a clumsy phrase is a real cost. Have someone who speaks each language read their column and fix it there.
- Translating the letter itself (`full_translation`) still needs the model. Only the interface works offline.
- Add a short terms-of-use and a first-use notice before real users upload anything.

## Privacy notes

The server does not store or log letter content, and responses are sent with `Cache-Control: no-store`. Your model provider's own data-retention terms still apply, so read them before making any promise to users.

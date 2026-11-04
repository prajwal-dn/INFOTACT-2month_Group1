<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Project rules
- This app is a frontend only. Capture (SocketCAN/vcan0), frequency analysis and Isolation Forest scoring live in the Linux Python backend; never port detection or capture logic into `src/`.
- All backend access goes through the `ApiClient` interface in `src/lib/api/client.ts`; `http-client.ts` targets the future FastAPI service and `demo-client.ts` serves labelled demo data. Components never call `fetch` directly.
- Response shapes are zod schemas in `src/lib/api/schemas.ts`; the HTTP client validates every response with them so backend contract drift fails loudly.
- Backend data is fetched client-side with TanStack Query (no route loaders) because the backend runs on the user's machine and is unreachable from SSR.
- Every screen that shows demo data must render the demo indicator from `src/components/app/DemoNotice.tsx`.
- The endpoint contract for the FastAPI backend is documented in `docs/api-contract.md`; update it together with `schemas.ts`.
- Audit-log wording that differs between demo mode and real-backend mode lives in `src/lib/audit-messages.ts`; never inline a demo message in a component, and never let demo text claim a real capture or inference.

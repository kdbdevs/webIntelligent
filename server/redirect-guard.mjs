// Chromium response-stage guard: Playwright route handlers only see the first request
// of an HTTP redirect chain. Inspect Location before the browser follows each hop.
// Never request response bodies, cookie values, or authentication storage.
export function redirectGuard(context, inspect, onError) {
  const pages = new WeakMap();
  const ready = new WeakSet();
  const prepare = (page) => {
    if (pages.has(page)) return pages.get(page);
    const task = (async () => {
      const cdp = await context.newCDPSession(page);
      cdp.on('Fetch.requestPaused', (event) => {
        (async () => {
          const location = event.responseHeaders?.find(
            (h) => h.name.toLowerCase() === 'location',
          )?.value;
          if ([301, 302, 303, 307, 308].includes(event.responseStatusCode) && location) {
            const url = new URL(location, event.request.url).href;
            const method =
              (event.responseStatusCode === 303 && event.request.method !== 'HEAD') ||
              ([301, 302].includes(event.responseStatusCode) && event.request.method === 'POST')
                ? 'GET'
                : event.request.method;
            const reason = await inspect({
              page,
              source: event.request.url,
              url,
              status: event.responseStatusCode,
              request: {
                url: () => url,
                method: () => method,
                isNavigationRequest: () => event.resourceType === 'Document',
                frame: () => page.mainFrame(),
                postData: () =>
                  method === event.request.method ? event.request.postData || null : null,
              },
            });
            if (reason) {
              await cdp.send('Fetch.failRequest', {
                requestId: event.requestId,
                errorReason: 'BlockedByClient',
              });
              return;
            }
          }
          await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
        })().catch(async () => {
          if (!page.isClosed()) onError();
          await cdp
            .send('Fetch.failRequest', {
              requestId: event.requestId,
              errorReason: 'BlockedByClient',
            })
            .catch(() => {});
        });
      });
      await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Response' }] });
      ready.add(page);
    })();
    pages.set(page, task);
    return task;
  };
  prepare.ready = (page) => ready.has(page);
  return prepare;
}

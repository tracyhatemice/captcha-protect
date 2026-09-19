FROM mcr.microsoft.com/playwright:v1.63.0-noble
WORKDIR /e2e
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN npm init -y >/dev/null && npm install --no-audit --no-fund playwright@1.63.0
COPY e2e.mjs .
ENTRYPOINT ["node", "e2e.mjs"]

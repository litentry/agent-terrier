FROM public.ecr.aws/docker/library/node@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /opt/terrier
COPY packages/package.json packages/package-lock.json ./packages/
COPY packages/agentkeys-dsh/package.json ./packages/agentkeys-dsh/
COPY packages/agent-terrier-runtime/package.json ./packages/agent-terrier-runtime/
RUN npm ci --prefix packages --ignore-scripts --no-audit --no-fund
COPY packages/agentkeys-dsh/src ./packages/agentkeys-dsh/src
COPY packages/agentkeys-dsh/tsconfig.json packages/agentkeys-dsh/tsconfig.build.json ./packages/agentkeys-dsh/
RUN npm run build --prefix packages && npm prune --prefix packages --omit=dev --ignore-scripts --no-audit --no-fund

FROM public.ecr.aws/docker/library/node@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS runtime
WORKDIR /opt/terrier
ENV NODE_ENV=production
COPY --from=build /opt/terrier/packages/node_modules ./packages/node_modules
COPY --from=build /opt/terrier/packages/agentkeys-dsh/lib ./packages/agentkeys-dsh/lib
COPY packages/agentkeys-dsh/package.json packages/agentkeys-dsh/README.md ./packages/agentkeys-dsh/
COPY packages/agent-terrier-runtime/package.json packages/agent-terrier-runtime/start.mjs ./packages/agent-terrier-runtime/
COPY presets/local-models.json ./presets/local-models.json
COPY LICENSE NOTICE ./
COPY LICENSES ./LICENSES
USER 1000:1000
ENTRYPOINT ["node", "packages/agent-terrier-runtime/start.mjs"]

FROM runtime AS qualification
COPY packages/agent-terrier-runtime/runtime.test.mjs packages/agent-terrier-runtime/test-support.mjs packages/agent-terrier-runtime/qualify-model.mjs ./packages/agent-terrier-runtime/
ENTRYPOINT ["node", "--test", "packages/agent-terrier-runtime/runtime.test.mjs"]

FROM runtime AS final

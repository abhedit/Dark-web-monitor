FROM node:24-bookworm-slim
WORKDIR /app
COPY --chown=node:node . .
RUN mkdir -p data && chown node:node data
USER node
ENV BIND=0.0.0.0
EXPOSE 8080
CMD ["node","server.js"]

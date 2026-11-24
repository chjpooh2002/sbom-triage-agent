FROM scratch AS base
WORKDIR /workspace
COPY package*.json .
RUN ["npm", "ci", "--production"]

FROM base
COPY package.json /service/manifest.json

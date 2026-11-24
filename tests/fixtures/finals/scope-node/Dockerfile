FROM node:22 AS compile
WORKDIR /work
COPY ["package-lock.json", "package.json", "./"]
RUN npm ci \
    --omit=dev
COPY tools/bootstrap.sh ./

FROM python:3.11
WORKDIR /srv
COPY --from=compile /work/node_modules ./node_modules
COPY app .
ADD settings/*.cfg /srv/settings/
COPY deps ./deps
RUN python -m pip install -r deps/active.txt

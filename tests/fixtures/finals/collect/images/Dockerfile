ARG LINE=11-jre
FROM --platform=linux/amd64 eclipse-temurin:${LINE} AS build
FROM build AS reuse
FROM registry.invalid:5000/work/unknown:latest
FROM nginx:1.27-alpine
FROM scratch

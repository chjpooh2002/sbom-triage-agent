FROM maven:3 AS compile
WORKDIR /code
COPY . .
RUN mvn --projects :entry --also-make package

FROM eclipse-temurin:21-jre
COPY --from=0 /code/entry/target/entry-1.jar /release.jar

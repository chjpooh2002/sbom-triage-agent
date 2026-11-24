FROM maven:3 AS compile
WORKDIR /code
COPY . .
RUN mvn -pl :app -am -DskipTests package

FROM eclipse-temurin:21-jre
COPY --from=compile /code/app/target/*.jar /release.jar

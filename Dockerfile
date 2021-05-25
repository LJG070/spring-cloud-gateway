FROM openjdk:11-jdk
ARG JAR_FILE=target/*.jar
EXPOSE 8000
ADD ${JAR_FILE} gateway.jar
ENTRYPOINT ["java","-jar","/gateway.jar"]
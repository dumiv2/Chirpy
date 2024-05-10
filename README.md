# Football Playground Booking System

The football playground booking system is a web application designed to facilitate the booking of football playgrounds for matches and events. It allows users to browse available playgrounds, schedule matches, and manage bookings.

## Prerequisites

- Go
- Docker
- Jenkins
- Kubernetes

## Building the Docker Image

First, we'll need to build a Docker image for Chirpy. This can be done by creating a Dockerfile with the necessary instructions to build the image.

Once the Dockerfile is created, we can build the image by running the following command in a kaniko container: 

```
/kaniko/executor --context `pwd` --destination conmeobeou1253/go-app:1.0
```

## Deploying with Jenkins and Kubernetes

Next, we'll use Jenkins to automate the deployment of Chirpy to Kubernetes. Jenkins will be used to build the Docker image, push it to a container registry, and deploy it to Kubernetes.

First, we'll need to create a Jenkins pipeline that includes the necessary steps to build, push, and deploy the image. You can find the Jenkinsfile in the root of the directory.

Once the Jenkins pipeline is set up, we can trigger it to automatically build, push, and deploy Chirpy to Kubernetes.

That's it! We've successfully built and deployed Chirpy using Go, Docker, Jenkins, and Kubernetes. 😊
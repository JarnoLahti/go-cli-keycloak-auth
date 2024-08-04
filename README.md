# Authenticate cli application with keycloak

This is a simple cli application that demonstrates how to authenticate a cli application with keycloak. Implementaion is part of a blog post that I wrote on [my blog]().

## Running the application

If you wish to run the application you will need to have a keycloak server running.
```bash
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/Keycloak/Keycloak:25.0.2 start-dev  
```

Once the keycloak server is running you need to create a new client to the master realm. You can follow steps defined in the blog post to create a new client.

#### Authenticate
```bash
go run main.go auth
```
#### Get user
```bash
go run main.go get-user
```

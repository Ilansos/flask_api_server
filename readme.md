# Flask API Server

This Flask API server provides secure access to a MongoDB database and implements various security measures. This guide covers configuring variables, managing users, building and deploying the Docker image, and deploying the application to a MicroK8s cluster.

## Features

1. **JWT Authentication:** Securely manage access using JWT tokens.
2. **IP Whitelisting:** Restrict access to specific IP addresses.
3. **Blacklist:** Prevents access from blacklisted IPs.
4. **Database Integration:** Connects to a MongoDB database for data storage and retrieval.
5. **Middleware:** Custom middleware for logging, honeypot functionality, and blacklisting.

## 1. Security Measures

This project focuses on API security, implementing measures directly at the application layer:

1. **JWT Authentication:** 
   - Securely manages access by issuing JWT tokens upon successful login.
   - Tokens are signed with a secret key to prevent forgery.
   - Tokens have an expiry time to prevent reuse.

2. **IP Whitelisting and Blacklisting:**
   - Allows only requests from specific IP addresses listed in `whitelist.txt`.
   - Requests from IP addresses listed in `blacklist.txt` are blocked.
   - IP lists are dynamically refreshed to ensure up-to-date access control.

3. **Honeypot Middleware:**
   - Logs and blacklists IPs attempting to access non-existent routes.
   - Provides mock credentials to these IPs, further trapping potential attackers.

4. **Logging Middleware:**
   - Logs all incoming requests, recording their method, path, and originating IP.
   - Helps track unauthorized access attempts and identify patterns.

5. **Secure Data Handling:**
   - Database queries are secured, preventing unauthorized access.
   - Passwords are securely hashed and stored, protecting against leaks and misuse.

## Disclaimer

The security measures provided by this server are implemented at the application layer. For a comprehensive security strategy, additional measures such as network-level firewalls, intrusion detection systems (IDS), and regular security audits should be considered. It's crucial to build a multi-layered security approach when deploying this server in a production environment.

## Getting Started

First, clone the repository to your local machine and change into the project directory:

```bash
git clone https://github.com/Ilansos/NistCVEs2Slack.git
cd NistCVEs2Slack
```

## Install Docker

Install Docker on your system by following the instructions on the official Docker website:
[Install Docker](https://docs.docker.com/get-docker/)

## Install MicroK8s

Install MicroK8s using the following command:

```bash
sudo snap install microk8s --classic
```

## Enable MicroK8s Addons

Enable necessary MicroK8s addons, including DNS and the registry:


```bash
sudo microk8s enable dns registry
```

## SSL Certificate

To ensure secure communication, create a self-signed SSL certificate:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
```

This creates a 2048-bit RSA key and a self-signed certificate valid for one year. Follow the prompts to fill in the necessary details.

## Using the Local Docker Registry

MicroK8s includes a built-in Docker registry where you can push your images. It is available at localhost:32000. Use this registry to manage local images.
Create Docker Image

#### Build the Docker image:

```bash
docker build -t localhost:32000/api_server:v1 .
```

#### Push the image to the local registry:

```bash
docker push localhost:32000/api_server:v1
```

## 2. Configuration

### Creating Kubernetes Secrets

To manage sensitive information securely, store it as Kubernetes Secrets:
  
####  1- Users and Passwords:

   - **Users:** Store hashed passwords as key-value pairs in `secrets.yaml`.

####  2- Hashing Passwords:

    - To hash the users password run `python3 generate_hashed_password.py` 
    - This script will request an imput of the user password and will print the hashed password.  

####  3- Base64 Encode the Values: Before creating the secrets, encode the values you want to store in Base64 format. For example:
```bash
echo -n "YOUR JWT_SECRET_KEY" | base64
echo -n "YOUR secret" | base64
echo -n "YOUR backend_secret" | base64
echo -n "YOUR user1 hashed password" | base64
echo -n "YOUR user2 hashed password" | base64
```

####  4- Define the Secret in the secrets.yaml File replacing the placeholders with the actual Base64-encoded strings:
```yaml  
apiVersion: v1
kind: Secret
metadata:
  name: api-secrets
type: Opaque
data:
  JWT_SECRET_KEY: <base64-encoded-key>
  secret: <base64-encoded-secret>
  backend_secret: <base64-encoded-backend-secret>
  user1: <base64_encoded_hashed_password_for_user1> # Set the key <user1> with the real username
  user2: <base64_encoded_hashed_password_for_user2> # Set the key <user2> with the real username
```
    
#### 5- If you modify the username, update the deployment.yaml file to match the new username:

```yaml
- name: user1 
    valueFrom:
    secretKeyRef:
        name: api-secrets
        key: user1 # Modify this with the real username
```

#### 6- IP Whitelisting and Blacklisting:

**IP Lists:**

    Update whitelist.txt and blacklist.txt in ip_lists.yaml with valid IP addresses for access control.

**ConfigMap:**

    Ensure ip_lists.yaml contains valid IP addresses and apply it to the cluster.

## 3. Deploying the Application

### Apply Secrets:

Ensure secrets.yaml contains base64-encoded values and apply it:

```bash
kubectl apply -f secrets.yaml
```

### Apply ConfigMap:

Ensure ip_lists.yaml is correctly configured and apply it:

```bash
kubectl apply -f ip_lists.yaml
```

### Deployment:

Ensure deployment.yaml references the correct Docker image and contains necessary environment variables. Apply it:

```bash
kubectl apply -f deployment.yaml
```

### Service:

Expose the server by applying service.yaml:

```bash
kubectl apply -f service.yaml
```

## 4. Checking the Server

To ensure the server is functioning correctly:

### Deployment Status:

Check the deployment's status with:

```bash
kubectl get pods
```

### Pod Logs:

Check the logs of a specific pod to see request activities and potential errors:

```bash
kubectl logs <pod-name>
```

### Entering the Pod Shell:

To access the shell of the API server for direct inspection:

```bash
kubectl exec -it <pod-name> /bin/bash
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

### MIT License
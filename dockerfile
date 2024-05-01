# Base Image
FROM python:3.10-slim
# Set Working Directory
WORKDIR /app
# Copy Application Files
COPY . /app
# Install Dependencies
RUN pip install --no-cache-dir -r requirements.txt
# Expose the Application Port
EXPOSE 5000
# Define the command to run the application
CMD ["python", "api_server.py"]

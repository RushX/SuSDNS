 
#    * SuSDNS - Proprietary Software
#    * Copyright (c) 2024 Rushikesh Muley. All rights reserved.
#    *
#    * This file is part of SuSDNS. Unauthorized copying, modification, or distribution of this file,
#    * via any medium, is strictly prohibited without prior written permission from the author.
#    *
#    * For inquiries, contact: Rushikesh Muley (rushikeshmuley@outlook.com)

# Use the official Python image
FROM python:3.8-slim

# Set the working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . /app/

# Expose the Flask app port
EXPOSE 5000

# Run the Flask app
CMD ["python", "app.py"]

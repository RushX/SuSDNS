 
#   * SuSDNS - Proprietary Software
#   * Copyright (c) 2024 Rushikesh Muley. All rights reserved.
#   *
#   * This file is part of SuSDNS. Unauthorized copying, modification, or distribution of this file,
#   * via any medium, is strictly prohibited without prior written permission from the author.
#   *
#   * For inquiries, contact: Rushikesh Muley (rushikeshmuley@outlook.com)
  
FROM nginx:alpine

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy the JSON response file
COPY response.json /usr/share/nginx/html/response.json

# Expose port 80
EXPOSE 80

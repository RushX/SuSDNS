 
#   * SuSDNS - Proprietary Software
#   * Copyright (c) 2024 Rushikesh Muley. All rights reserved.
#   *
#   * This file is part of SuSDNS. Unauthorized copying, modification, or distribution of this file,
#   * via any medium, is strictly prohibited without prior written permission from the author.
#   *
#   * For inquiries, contact: Rushikesh Muley (rushikeshmuley@outlook.com)
  
FROM redis:latest

# Copy custom redis configuration (optional)
COPY redis.conf /usr/local/etc/redis/redis.conf

# Expose the Redis port
EXPOSE 6379

# Start Redis server
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]
